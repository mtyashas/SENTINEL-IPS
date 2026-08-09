"""
dashboard/server.py

Purpose: Embedded Flask + Flask-SocketIO server for the SENTINEL IPS v2.0
         live dashboard. Runs inside sentinel.py's own process so it can
         read LiveMonitor/AttackMap directly -- no IPC. A background
         thread builds a JSON-safe snapshot (KPIs, alert stream,
         throughput, serialized Plotly figures, system health) roughly
         every `tick_s` seconds and pushes it to every connected browser
         as a "dashboard_update" Socket.IO event; LiveMonitor.push_event()
         is wrapped (on the instance, not the class -- live_monitor.py is
         never modified) to also trigger an immediate out-of-cycle emit,
         so a new alert doesn't wait for the next scheduled tick.

Inputs:  a running LiveMonitor and AttackMap instance (shared with
         SentinelIPS -- see sentinel.py's `monitor`/`attack_map`
         properties).
Outputs: none directly -- serves the built React app (dashboard/web/dist)
         and emits "dashboard_update" Socket.IO events to connected
         clients.

Usage:
    from dashboard.server import start_dashboard_server
    handle = start_dashboard_server(ips.monitor, ips.attack_map)
    ...
    handle.stop()
"""

import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from flask import Flask, send_from_directory
from flask_socketio import SocketIO

from config import MITRE_ATTACK_MAP
from dashboard.attack_map import AttackMap
from dashboard.live_monitor import LiveMonitor

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parent.parent
_WEB_DIST = _ROOT / "dashboard" / "web" / "dist"

_TICK_S_DEFAULT = 2.0

# Neumorphic theme tokens -- must match dashboard/web/src/theme.css exactly.
NEU_BASE = "#1B2130"
NEU_LIGHT = "#262E42"
NEU_DARK = "#10141D"
NEU_ACCENT = "#5AD1E6"
NEU_INK = "#EAF0FA"
NEU_INK_DIM = "#8996AD"

NEU_SEVERITY_COLOURS: dict[str, str] = {
    "CRITICAL": "#FF5C7A",
    "HIGH": "#FFA24D",
    "MEDIUM": "#FFD65C",
    "LOW": "#5CE6A6",
    "INFO": "#6FA8FF",
}

_TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact", "Multiple",
]


def _create_app() -> Flask:
    """Flask app that serves the built React frontend (dashboard/web/dist)."""
    app = Flask(__name__, static_folder=str(_WEB_DIST), static_url_path="")

    @app.route("/")
    def index():
        index_path = _WEB_DIST / "index.html"
        if not index_path.exists():
            return (
                "Dashboard frontend not built. Run: "
                "cd dashboard/web && npm install && npm run build",
                503,
            )
        return send_from_directory(str(_WEB_DIST), "index.html")

    return app


def _system_health() -> dict:
    """CPU/RAM/disk snapshot via psutil. Returns None fields if psutil is
    missing or disk_usage('/') fails (matches dashboard/app.py's existing
    defensive fallback for the same call on Windows)."""
    try:
        import psutil
    except ImportError:
        return {
            "cpu_pct": None, "ram_pct": None,
            "ram_used_gb": None, "ram_total_gb": None, "disk_free_gb": None,
        }

    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory()
    try:
        disk_free_gb: Optional[float] = round(psutil.disk_usage("/").free / (1024 ** 3), 2)
    except Exception:
        disk_free_gb = None

    return {
        "cpu_pct": cpu,
        "ram_pct": ram.percent,
        "ram_used_gb": round(ram.used / (1024 ** 3), 2),
        "ram_total_gb": round(ram.total / (1024 ** 3), 2),
        "disk_free_gb": disk_free_gb,
    }


def _theme_figure(fig, geo: bool = False) -> None:
    """Re-theme a Plotly figure to the neumorphic palette in place. `geo`
    also themes the map-specific layout (land/ocean/country colours) used
    by scatter-geo and choropleth figures."""
    fig.update_layout(
        paper_bgcolor=NEU_BASE,
        plot_bgcolor=NEU_BASE,
        font=dict(color=NEU_INK),
    )
    if geo:
        fig.update_geos(
            bgcolor=NEU_BASE,
            landcolor=NEU_LIGHT,
            oceancolor=NEU_DARK,
            countrycolor=NEU_INK_DIM,
            coastlinecolor=NEU_INK_DIM,
        )


def _figure_to_json(fig, geo: bool = False) -> Optional[dict]:
    """Re-theme and serialize a Plotly figure to a JSON-safe dict (or None
    if the figure itself is None -- e.g. plotly isn't installed)."""
    if fig is None:
        return None
    _theme_figure(fig, geo=geo)
    return json.loads(fig.to_json())


def _attack_bar_figure(attack_counts: dict[str, int]):
    """Horizontal bar chart of attack-type counts, matching the old
    dashboard/app.py panel 4 but re-themed."""
    try:
        import plotly.graph_objects as go
    except ImportError:
        return None

    items = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
    labels = [k for k, _ in items]
    values = [v for _, v in items]

    fig = go.Figure(go.Bar(
        x=values, y=labels, orientation="h",
        marker=dict(color=NEU_ACCENT),
    ))
    fig.update_layout(
        margin=dict(l=0, r=10, t=10, b=0),
        yaxis=dict(autorange="reversed"),
        height=300,
    )
    return fig


def _severity_pie_figure(severity_counts: dict[str, int]):
    """Donut chart of severity counts, matching the old dashboard/app.py
    panel 5 but with the neumorphic severity palette."""
    try:
        import plotly.graph_objects as go
    except ImportError:
        return None

    labels = list(severity_counts.keys())
    values = list(severity_counts.values())
    colours = [NEU_SEVERITY_COLOURS.get(s, "#78909C") for s in labels]

    fig = go.Figure(go.Pie(
        labels=labels, values=values,
        marker=dict(colors=colours),
        textinfo="label+percent",
        hole=0.4,
    ))
    fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=300, showlegend=True)
    return fig


def _mitre_heatmap_figure(attack_counts: dict[str, int]):
    """MITRE ATT&CK tactic x technique coverage heatmap, matching the old
    dashboard/app.py panel 8 but re-themed."""
    try:
        import plotly.graph_objects as go
    except ImportError:
        return None

    mitre_rows: dict[str, dict[str, int]] = {}
    for attack, meta in MITRE_ATTACK_MAP.items():
        tactic = meta.get("tactic", "Unknown")
        technique = meta.get("technique", "T0000")
        count = attack_counts.get(attack, 0)
        mitre_rows.setdefault(tactic, {})[f"{technique}\n{attack}"] = count

    if not mitre_rows:
        return go.Figure()

    tactics = [t for t in _TACTIC_ORDER if t in mitre_rows]
    techniques = sorted({tech for row in mitre_rows.values() for tech in row})
    z_matrix = [[mitre_rows[t].get(tech, 0) for tech in techniques] for t in tactics]

    fig = go.Figure(go.Heatmap(
        z=z_matrix, x=techniques, y=tactics,
        colorscale="YlOrRd", showscale=True,
        hovertemplate="Tactic: %{y}<br>Technique: %{x}<br>Count: %{z}<extra></extra>",
    ))
    fig.update_layout(
        xaxis=dict(tickangle=-45, tickfont=dict(size=9)),
        yaxis=dict(tickfont=dict(size=10)),
        margin=dict(l=10, r=10, t=10, b=80),
        height=320,
    )
    return fig


def build_snapshot_payload(monitor: LiveMonitor, amap: AttackMap) -> dict:
    """
    Build the JSON-safe payload emitted as the "dashboard_update"
    Socket.IO event.
    """
    snap = monitor.snapshot()
    return {
        "monitor": snap,
        "top_countries": amap.top_countries(10),
        "unique_ips": amap.total_unique_ips(),
        "health": _system_health(),
        "figures": {
            "world_map": _figure_to_json(amap.scatter_geo_figure(), geo=True),
            "choropleth": _figure_to_json(amap.choropleth_figure(), geo=True),
            "mitre_heatmap": _figure_to_json(_mitre_heatmap_figure(snap["attack_counts"])),
            "attack_bar": _figure_to_json(_attack_bar_figure(snap["attack_counts"])),
            "severity_pie": _figure_to_json(_severity_pie_figure(snap["severity_counts"])),
        },
    }


def _emitter_loop(
    monitor: LiveMonitor,
    amap: AttackMap,
    socketio: SocketIO,
    tick_s: float,
    stop_event: threading.Event,
) -> None:
    while not stop_event.is_set():
        try:
            payload = build_snapshot_payload(monitor, amap)
            socketio.emit("dashboard_update", payload)
        except Exception:
            logger.exception("Dashboard emitter tick failed; skipping this tick")
        stop_event.wait(tick_s)


def _install_instant_emit(monitor: LiveMonitor, amap: AttackMap, socketio: SocketIO) -> None:
    """
    Wrap monitor.push_event() so a new detection triggers an immediate
    out-of-cycle emit instead of waiting for the next scheduled tick.
    Wraps the bound method on this *instance* only --
    dashboard/live_monitor.py itself is never modified.
    """
    original_push_event = monitor.push_event

    def _push_and_emit(event: dict) -> None:
        original_push_event(event)
        try:
            socketio.emit("dashboard_update", build_snapshot_payload(monitor, amap))
        except Exception:
            logger.exception("Dashboard instant-emit failed")

    monitor.push_event = _push_and_emit  # type: ignore[method-assign]


@dataclass
class DashboardServerHandle:
    """Returned by start_dashboard_server(). Call .stop() to signal the
    emitter thread to exit; the HTTP/Socket.IO server thread is a daemon
    thread and exits with the parent process (see the comment on that
    thread in start_dashboard_server for why no graceful HTTP shutdown is
    implemented)."""

    stop_event: threading.Event
    host: str
    port: int

    def stop(self) -> None:
        self.stop_event.set()
        logger.info("Dashboard emitter thread stop requested")


def start_dashboard_server(
    monitor: LiveMonitor,
    amap: AttackMap,
    host: str = "0.0.0.0",
    port: int = 5000,
    tick_s: float = _TICK_S_DEFAULT,
) -> DashboardServerHandle:
    """
    Start the embedded dashboard server as two daemon background threads
    (HTTP/Socket.IO server, and the periodic snapshot emitter) and return
    immediately -- does not block the caller's own loop.
    """
    app = _create_app()
    socketio = SocketIO(app, cors_allowed_origins="*")
    stop_event = threading.Event()

    _install_instant_emit(monitor, amap, socketio)

    threading.Thread(
        target=_emitter_loop,
        args=(monitor, amap, socketio, tick_s, stop_event),
        daemon=True,
        name="dashboard-emitter",
    ).start()

    threading.Thread(
        # ponytail: daemon thread, no graceful HTTP server shutdown --
        # acceptable for a local lab tool stopped via Ctrl+C on the parent
        # sentinel.py process; add a real shutdown path if this ever needs
        # to run detached from sentinel.py's lifecycle.
        target=lambda: socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True),
        daemon=True,
        name="dashboard-http",
    ).start()

    display_host = "localhost" if host == "0.0.0.0" else host
    logger.info("Dashboard server started at http://%s:%d", display_host, port)
    return DashboardServerHandle(stop_event=stop_event, host=host, port=port)
