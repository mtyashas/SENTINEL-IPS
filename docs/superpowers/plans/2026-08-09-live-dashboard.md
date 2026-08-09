# Live Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the demo-data Streamlit dashboard with a real live dashboard — a Flask-SocketIO server embedded in `sentinel.py`'s own process, and a neumorphic React/Vite frontend — so the dashboard shows actual `sentinel.py live` detections instead of synthetic data.

**Architecture:** `sentinel.py live` starts an embedded Flask-SocketIO server (`dashboard/server.py`) in background threads, sharing the same `LiveMonitor`/`AttackMap` instances the detection pipeline already writes to — no IPC. A background thread emits a `dashboard_update` Socket.IO event roughly every 2s (plus instantly on every new detection); the React frontend renders it into 9 panels styled as a neumorphic SOC dashboard.

**Tech Stack:** Flask + Flask-SocketIO (backend, threading async mode — no eventlet/gevent), React + Vite (frontend), react-plotly.js + plotly.js-dist-min (chart rendering), socket.io-client (live transport).

**Spec:** `docs/superpowers/specs/2026-08-09-live-dashboard-design.md`

## Global Constraints

- Python: type hints on every function signature, `logging` not `print`, `pathlib.Path` for file paths, no global side effects on import (verbatim from `CLAUDE.md`'s Engineering Standards — applies to `dashboard/server.py` and `sentinel.py` changes; does not apply to the JS frontend).
- Backend framework: Flask + Flask-SocketIO, default **threading** async mode. Do not add `eventlet` or `gevent` — not needed at this scale and adds two heavy new dependencies for no benefit here.
- Frontend chart library: `react-plotly.js` used via its documented factory pattern with `plotly.js-dist-min` (the full-trace-support minified bundle — `plotly.js-basic-dist` does **not** include `choropleth`/`scattergeo`, which this dashboard needs).
- Neumorphic color tokens (verbatim from the spec — use these exact hex values everywhere they appear, Python and CSS alike):
  `--neu-base:#1B2130` `--neu-light:#262E42` `--neu-dark:#10141D` `--neu-accent:#5AD1E6` `--neu-ink:#EAF0FA` `--neu-ink-dim:#8996AD`
  Severity: `CRITICAL:#FF5C7A` `HIGH:#FFA24D` `MEDIUM:#FFD65C` `LOW:#5CE6A6` `INFO:#6FA8FF`
- Typography: Barlow Condensed (700/900) for headers/large numbers, IBM Plex Sans (400/600) for UI text, IBM Plex Mono (400/500) for data — via Google Fonts `<link>` in `index.html` (this is a normal web app, not an Artifact — no CSP blocking font CDNs, so no need to inline as data URIs).
- **Live-only in the product**: `sentinel.py`/`dashboard/server.py` never inject synthetic data. The one synthetic-data script this plan creates (`lab/run_dashboard_dev.py`) is explicitly a `lab/`-scoped developer QA harness, never imported by `sentinel.py` or shipped as a dashboard feature.
- `dashboard/app.py`, `dashboard/live_monitor.py`, `dashboard/attack_map.py` are reused as-is — `live_monitor.py` is never modified; `app.py` is never modified or deleted; `attack_map.py` is never modified (its returned Plotly figures are re-themed by the *caller* via `fig.update_layout(...)`, not by editing the file).

---

## File Structure

```
dashboard/
├── server.py                NEW  — Flask + Flask-SocketIO app, emitter thread
└── web/                      NEW  — Vite + React frontend
    ├── package.json
    ├── vite.config.js
    ├── index.html
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── theme.css
        └── components/
            ├── KpiRow.jsx
            ├── SystemHealth.jsx
            ├── ThroughputChart.jsx
            ├── AlertTable.jsx
            ├── PlotlyPanel.jsx
            ├── AttackBarChart.jsx
            ├── SeverityPie.jsx
            ├── WorldMap.jsx
            ├── Choropleth.jsx
            └── MitreHeatmap.jsx

lab/
├── verify_dashboard_snapshot_serialization.py   NEW — JSON round-trip check
└── run_dashboard_dev.py                          NEW — dev-only QA harness (synthetic data)

sentinel.py            MODIFIED — _run_live() starts/stops the dashboard server;
                                   _run_health() module list gains "dashboard.server"
requirements.txt       MODIFIED — add flask-socketio
```

---

### Task 1: Backend server skeleton — snapshot payload, Flask+SocketIO wiring, dev harness

**Files:**
- Modify: `requirements.txt`
- Create: `dashboard/server.py`
- Create: `lab/verify_dashboard_snapshot_serialization.py`
- Create: `lab/run_dashboard_dev.py`

**Interfaces:**
- Consumes: `dashboard.live_monitor.LiveMonitor` (`.snapshot() -> dict`, `.push_event(dict) -> None`, `.record_throughput(float) -> None`), `dashboard.attack_map.AttackMap` (`.top_countries(n) -> list[tuple[str,int]]`, `.total_unique_ips() -> int`, `.ingest(dict) -> None`) — both unmodified, as already used by `sentinel.py`.
- Produces (used by Task 2 and Task 3):
  - `build_snapshot_payload(monitor: LiveMonitor, amap: AttackMap) -> dict` — keys `monitor`, `top_countries`, `unique_ips`, `health`, `figures` (figures is `{}` until Task 2).
  - `start_dashboard_server(monitor: LiveMonitor, amap: AttackMap, host: str = "0.0.0.0", port: int = 5000, tick_s: float = 2.0) -> DashboardServerHandle`
  - `class DashboardServerHandle` with `.stop() -> None`

- [ ] **Step 1: Add flask-socketio to requirements.txt and install it**

Edit `requirements.txt`, in the "Web framework" section:

```
# Web framework
flask>=3.0.0
flask-socketio>=5.3.0
werkzeug>=3.0.0
```

Run: `pip install flask-socketio>=5.3.0`
Expected: installs cleanly (pulls in `python-socketio`, `python-engineio` as transitive deps).

- [ ] **Step 2: Write dashboard/server.py**

```python
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

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from flask import Flask, send_from_directory
from flask_socketio import SocketIO

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


def build_snapshot_payload(monitor: LiveMonitor, amap: AttackMap) -> dict:
    """
    Build the JSON-safe payload emitted as the "dashboard_update"
    Socket.IO event.

    NOTE: `figures` is populated by _build_figures() added in Task 2 of
    docs/superpowers/plans/2026-08-09-live-dashboard.md -- this stage
    returns an empty dict so the server/emitter wiring can be verified
    before the Plotly re-theming logic exists.
    """
    snap = monitor.snapshot()
    return {
        "monitor": snap,
        "top_countries": amap.top_countries(10),
        "unique_ips": amap.total_unique_ips(),
        "health": _system_health(),
        "figures": {},
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
```

- [ ] **Step 3: Write the JSON round-trip verify script**

```python
"""
lab/verify_dashboard_snapshot_serialization.py

Purpose: Self-check that dashboard.server.build_snapshot_payload() always
         produces a payload that round-trips cleanly through
         json.dumps/json.loads. This is the one place a silent
         serialization break (a non-JSON-safe value leaking into a Plotly
         figure, or a NaN in a numpy-derived stat) could hide behind a
         working-looking UI -- Socket.IO's own encoder would raise at
         emit time in production; this catches it standalone, without
         needing a running server. Re-run unchanged after Task 2 adds
         real Plotly figures -- Check 3 validates whatever is in
         `figures` at the time, empty or populated.

Usage:
    python lab/verify_dashboard_snapshot_serialization.py
"""
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dashboard.attack_map import AttackMap
from dashboard.live_monitor import LiveMonitor
from dashboard.server import build_snapshot_payload

print("--- Check 1: empty monitor/amap payload round-trips through JSON ---")
monitor = LiveMonitor()
amap = AttackMap()
payload = build_snapshot_payload(monitor, amap)
decoded = json.loads(json.dumps(payload))
assert decoded["monitor"]["total_attacks"] == 0
assert decoded["top_countries"] == []
assert decoded["unique_ips"] == 0
print("PASS: empty payload round-trips")

print()
print("--- Check 2: populated payload round-trips; tuples decode as JSON arrays ---")
monitor.push_event({
    "attack_type": "DDoS", "src_ip": "203.0.113.10", "dst_ip": "10.0.0.5",
    "confidence": 0.97, "severity": "CRITICAL", "mitre_tactic": "Impact",
    "risk_score": 91.4, "action": "ip_block",
})
monitor.record_throughput(128_402.0)
amap.ingest({
    "lat": 37.09, "lon": -95.71, "country": "United States",
    "country_code": "USA", "city": "Unknown", "src_ip": "203.0.113.10",
    "attack_type": "DDoS", "severity": "CRITICAL",
})
payload = build_snapshot_payload(monitor, amap)
decoded = json.loads(json.dumps(payload))
assert decoded["monitor"]["total_attacks"] == 1
assert decoded["unique_ips"] == 1
assert decoded["top_countries"] == [["United States", 1]], decoded["top_countries"]
assert decoded["monitor"]["events_list"][0]["attack"] == "DDoS"
print("PASS: populated payload round-trips, top_countries tuples decode as lists")

print()
print("--- Check 3: every figure (once built) is a JSON-safe dict, not a raw Plotly object ---")
if decoded["figures"]:
    for name, fig in decoded["figures"].items():
        assert fig is None or isinstance(fig, dict), f"figure {name!r} did not serialize to a plain dict"
    print("PASS: all figures are JSON-safe dicts")
else:
    print("PASS: no figures yet (stub stage, expected before Task 2)")

print()
print("All checks passed.")
```

- [ ] **Step 4: Run the verify script**

Run: `python lab/verify_dashboard_snapshot_serialization.py`
Expected: three `PASS` lines, then `All checks passed.`

- [ ] **Step 5: Write the dev-only QA harness**

```python
"""
lab/run_dashboard_dev.py

Purpose: Manual QA harness for dashboard/server.py and dashboard/web --
         NOT part of the sentinel.py product surface. sentinel.py live is
         live-only (no synthetic data), per
         docs/superpowers/specs/2026-08-09-live-dashboard-design.md.
         This script starts the embedded dashboard server against a
         LiveMonitor/AttackMap fed a rotating stream of synthetic
         detection events, so the frontend can be developed and eyeballed
         in a browser without needing a real packet capture running.

Usage:
    python lab/run_dashboard_dev.py
    # then open http://localhost:5000
"""
import random
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from dashboard.attack_map import AttackMap
from dashboard.live_monitor import LiveMonitor
from dashboard.server import start_dashboard_server

_SAMPLE_ATTACKS = [
    ("DDoS", "HIGH", "Impact", "203.0.113.10", "United States", "USA", 37.09, -95.71),
    ("PortScan", "LOW", "Discovery", "198.51.100.5", "Russia", "RUS", 61.52, 105.31),
    ("BruteForce", "MEDIUM", "Initial Access", "192.0.2.88", "China", "CHN", 35.86, 104.19),
    ("Bot", "HIGH", "Persistence", "185.220.101.5", "Germany", "DEU", 51.16, 10.45),
    ("SQLInjection", "MEDIUM", "Execution", "203.0.113.77", "Brazil", "BRA", -14.23, -51.92),
    ("Infiltration", "CRITICAL", "Lateral Movement", "198.51.100.42", "North Korea", "PRK", 40.33, 127.51),
]


def main() -> None:
    monitor = LiveMonitor()
    amap = AttackMap()
    start_dashboard_server(monitor, amap)
    print("Dev dashboard running at http://localhost:5000 -- Ctrl+C to stop")

    rng = random.Random()
    try:
        while True:
            atk, sev, tactic, ip, country, code, lat, lon = rng.choice(_SAMPLE_ATTACKS)
            event = {
                "attack_type": atk, "severity": sev, "mitre_tactic": tactic,
                "src_ip": ip, "confidence": round(rng.uniform(0.65, 0.99), 3),
                "risk_score": round(rng.uniform(30, 98), 1), "action": "ip_block",
                "lat": lat + rng.uniform(-2, 2), "lon": lon + rng.uniform(-2, 2),
                "country": country, "country_code": code, "city": "Unknown",
            }
            monitor.push_event(event)
            amap.ingest(event)
            monitor.record_throughput(rng.uniform(800_000, 1_700_000))
            time.sleep(3)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Run the dev harness and confirm the server answers**

Run: `python lab/run_dashboard_dev.py` (leave running)
Run in a second terminal: `curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5000/`
Expected: `503` (frontend not built yet — expected at this stage; confirms the Flask route itself is reachable and returning the "not built" message rather than erroring). Stop the harness with Ctrl+C.

- [ ] **Step 7: Commit**

```bash
git add requirements.txt dashboard/server.py lab/verify_dashboard_snapshot_serialization.py lab/run_dashboard_dev.py
git commit -m "feat: add embedded dashboard server skeleton (Flask-SocketIO)"
```

---

### Task 2: Real Plotly figures — MITRE heatmap, attack bar, severity pie, geo re-theme

**Files:**
- Modify: `dashboard/server.py`

**Interfaces:**
- Consumes: `config.MITRE_ATTACK_MAP` (dict of `attack_name -> {"tactic": str, "technique": str, "name": str}`), `amap.scatter_geo_figure() -> Optional[go.Figure]`, `amap.choropleth_figure() -> Optional[go.Figure]` (both from Task 1's unmodified `attack_map.py`).
- Produces: `build_snapshot_payload(...)`'s `"figures"` key now populated with keys `world_map`, `choropleth`, `mitre_heatmap`, `attack_bar`, `severity_pie` (each a JSON dict or `None`).

- [ ] **Step 1: Add the figure builders and re-theming helpers to dashboard/server.py**

Add these imports at the top (after the existing imports):

```python
import json

from config import MITRE_ATTACK_MAP
```

Add this constant near the other `NEU_*` constants:

```python
_TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact", "Multiple",
]
```

Add these functions after `_system_health()`:

```python
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
```

- [ ] **Step 2: Wire the figures into build_snapshot_payload()**

Replace `"figures": {}` in `build_snapshot_payload` with:

```python
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
```

Also delete the now-stale docstring note about figures being added later (the paragraph starting `NOTE: `figures` is populated by...`).

- [ ] **Step 3: Re-run the verify script from Task 1 (unchanged file) to confirm figures are JSON-safe**

Run: `python lab/verify_dashboard_snapshot_serialization.py`
Expected: `PASS: all figures are JSON-safe dicts` now appears for Check 3 (instead of the "no figures yet" stub-stage message), plus the same Check 1/2 passes as before.

- [ ] **Step 4: Manually confirm the dev harness now emits real chart data**

Run: `python lab/run_dashboard_dev.py`
In a Python shell (separate process, same venv): 
```python
import socketio
sio = socketio.SimpleClient()
sio.connect("http://localhost:5000")
event = sio.receive(timeout=5)
print(event[0], list(event[1]["figures"].keys()))
sio.disconnect()
```
Expected: prints `dashboard_update ['world_map', 'choropleth', 'mitre_heatmap', 'attack_bar', 'severity_pie']`. Stop the harness with Ctrl+C.

- [ ] **Step 5: Commit**

```bash
git add dashboard/server.py
git commit -m "feat: build and re-theme the 5 Plotly figures for the live dashboard"
```

---

### Task 3: Wire the dashboard server into sentinel.py live mode

**Files:**
- Modify: `sentinel.py`

**Interfaces:**
- Consumes: `dashboard.server.start_dashboard_server(monitor, amap) -> DashboardServerHandle`, `DashboardServerHandle.stop() -> None` (both from Task 1/2).

- [ ] **Step 1: Import start_dashboard_server**

In `sentinel.py`, add to the Dashboard imports block (near line 124):

```python
# Dashboard
from dashboard.attack_map import AttackMap
from dashboard.live_monitor import LiveMonitor
from dashboard.server import start_dashboard_server
```

- [ ] **Step 2: Start the server at the top of _run_live()**

In `_run_live()`, right after `ips = SentinelIPS(...)` is constructed (around line 1059), add:

```python
    dashboard_handle = start_dashboard_server(ips.monitor, ips.attack_map)
    logger.info("Live dashboard: http://localhost:%d", dashboard_handle.port)
```

- [ ] **Step 3: Stop the server on shutdown**

In `_run_live()`'s `except KeyboardInterrupt:` block, alongside the existing `flow_sniffer.stop()` and `honeypot.stop()` calls, add:

```python
        dashboard_handle.stop()
```

- [ ] **Step 4: Add dashboard.server to the health-check module list**

In `_run_health()`'s `_modules` list (around line 1246), change:

```python
        "dashboard.live_monitor", "dashboard.attack_map",
```
to:
```python
        "dashboard.live_monitor", "dashboard.attack_map", "dashboard.server",
```

- [ ] **Step 5: Run the health check**

Run: `python sentinel.py health`
Expected: `OK  : 33/33`, `All 33 modules operational and wired into the pipeline.`, exit code 0.

Note: `dashboard.server` won't show up as "dead" in the pipeline-wiring check even though it's not a `self._xxx` attribute of `SentinelIPS` — that check only inspects `SentinelIPS.__init__`, and `start_dashboard_server` is called from the module-level `_run_live()` function, not from inside the class.

- [ ] **Step 6: Commit**

```bash
git add sentinel.py
git commit -m "feat: start the embedded dashboard server from sentinel.py live"
```

---

### Task 4: Frontend scaffold — Vite + React, dependencies, dev proxy, connectivity proof

**Files:**
- Create: `dashboard/web/package.json` (via `npm create vite`)
- Create: `dashboard/web/vite.config.js`
- Create: `dashboard/web/index.html`
- Create: `dashboard/web/src/main.jsx`
- Create: `dashboard/web/src/App.jsx`

**Interfaces:**
- Consumes: the `dashboard_update` Socket.IO event from Task 1/2, shape `{monitor, top_countries, unique_ips, health, figures}`.

- [ ] **Step 1: Scaffold the Vite React app**

```bash
cd dashboard
npm create vite@latest web -- --template react
cd web
npm install
npm install socket.io-client react-plotly.js plotly.js-dist-min
```

Expected: `dashboard/web/` now contains `package.json`, `src/`, `index.html`, etc.; `npm install` completes with no errors.

- [ ] **Step 2: Configure the dev proxy so socket.io traffic reaches Flask**

Replace the contents of `dashboard/web/vite.config.js`:

```js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/socket.io': {
        target: 'http://localhost:5000',
        ws: true,
      },
    },
  },
})
```

- [ ] **Step 3: Set the page title and add the Google Fonts link**

Replace `dashboard/web/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>SENTINEL IPS — SOC Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@700;900&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;600&display=swap"
      rel="stylesheet"
    />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
```

- [ ] **Step 4: Replace main.jsx (drop Vite's default CSS import)**

```jsx
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
```

- [ ] **Step 5: Replace App.jsx with a minimal connectivity proof**

```jsx
import { useEffect, useState } from 'react'
import { io } from 'socket.io-client'

export default function App() {
  const [connected, setConnected] = useState(false)
  const [data, setData] = useState(null)

  useEffect(() => {
    const socket = io()
    socket.on('connect', () => setConnected(true))
    socket.on('disconnect', () => setConnected(false))
    socket.on('dashboard_update', (payload) => setData(payload))
    return () => socket.disconnect()
  }, [])

  return (
    <div style={{ fontFamily: 'monospace', padding: 20 }}>
      <p>Connected: {connected ? 'yes' : 'no'}</p>
      <pre>{data ? JSON.stringify(data.monitor, null, 2) : 'waiting for data...'}</pre>
    </div>
  )
}
```

Delete `dashboard/web/src/App.css` and `dashboard/web/src/index.css` if `npm create vite` generated them (no longer referenced after this step).

- [ ] **Step 6: Manually verify the wire protocol end-to-end**

Terminal A: `python lab/run_dashboard_dev.py`
Terminal B: `cd dashboard/web && npm run dev`
Open `http://localhost:5173` in a browser.
Expected: page shows `Connected: yes` and a JSON dump of `monitor` that updates roughly every 3 seconds (matching the dev harness's event interval), with `total_attacks` incrementing. Stop both processes with Ctrl+C.

- [ ] **Step 7: Commit**

```bash
git add dashboard/web
git commit -m "feat: scaffold React/Vite dashboard frontend with live socket connectivity"
```

---

### Task 5: Neumorphic design tokens (theme.css)

**Files:**
- Create: `dashboard/web/src/theme.css`
- Modify: `dashboard/web/src/main.jsx`

**Interfaces:**
- Produces: CSS custom properties (`--neu-base`, `--neu-light`, `--neu-dark`, `--neu-accent`, `--neu-ink`, `--neu-ink-dim`, `--crit`, `--high`, `--med`, `--low`, `--info`) and utility classes (`.app`, `.header`, `.subheader`, `.banner-reconnecting`, `.kpis`, `.kpi`, `.panel`, `.grid-2`, `.grid-3`, `.alert-table`, `.chip` + severity modifiers, `.empty-state`) consumed by every component task from here on.

- [ ] **Step 1: Write theme.css**

```css
:root {
  --neu-base: #1B2130;
  --neu-light: #262E42;
  --neu-dark: #10141D;
  --neu-accent: #5AD1E6;
  --neu-ink: #EAF0FA;
  --neu-ink-dim: #8996AD;

  --crit: #FF5C7A;
  --high: #FFA24D;
  --med: #FFD65C;
  --low: #5CE6A6;
  --info: #6FA8FF;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--neu-base);
  color: var(--neu-ink);
  font-family: 'IBM Plex Sans', -apple-system, sans-serif;
}

.app {
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
}

.header {
  font-family: 'Barlow Condensed', sans-serif;
  font-weight: 900;
  font-size: 28px;
  letter-spacing: 0.02em;
  color: var(--neu-ink);
  margin: 0 0 4px;
}

.subheader {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 11px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--neu-accent);
  margin: 0 0 20px;
}

.banner-reconnecting {
  background: var(--neu-base);
  color: var(--high);
  border-radius: 12px;
  padding: 10px 16px;
  margin-bottom: 16px;
  box-shadow: inset 3px 3px 8px var(--neu-dark), inset -3px -3px 8px var(--neu-light);
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
}

.kpis {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 18px;
  margin-bottom: 20px;
}

.kpi {
  background: var(--neu-base);
  border-radius: 16px;
  padding: 14px 16px;
  box-shadow: 6px 6px 14px var(--neu-dark), -6px -6px 14px var(--neu-light);
}
.kpi .lbl {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--neu-ink-dim);
  margin-bottom: 8px;
}
.kpi .val {
  font-family: 'Barlow Condensed', sans-serif;
  font-weight: 700;
  font-size: 27px;
  color: var(--neu-ink);
  font-variant-numeric: tabular-nums;
}

.panel {
  background: var(--neu-base);
  border-radius: 18px;
  padding: 16px 18px;
  box-shadow: inset 5px 5px 12px var(--neu-dark), inset -5px -5px 12px var(--neu-light);
  margin-bottom: 20px;
}
.panel h3 {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--neu-ink-dim);
  margin: 0 0 12px;
  font-weight: 500;
}

.grid-2 {
  display: grid;
  grid-template-columns: 1fr 1.6fr;
  gap: 18px;
}

table.alert-table { width: 100%; border-collapse: collapse; font-size: 12px; }
table.alert-table th {
  text-align: left;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 9.5px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--neu-ink-dim);
  font-weight: 500;
  padding: 0 8px 8px 0;
}
table.alert-table td {
  padding: 7px 8px 7px 0;
  color: var(--neu-ink);
  font-family: 'IBM Plex Mono', monospace;
  font-variant-numeric: tabular-nums;
  border-bottom: 1px solid rgba(255, 255, 255, 0.04);
}

.chip {
  display: inline-block;
  font-family: 'IBM Plex Sans', sans-serif;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.03em;
  padding: 2px 8px;
  border-radius: 4px;
  background: var(--neu-base);
}
.chip.CRITICAL { color: var(--crit); box-shadow: 0 0 0 1px rgba(255, 92, 122, 0.35), 0 0 10px rgba(255, 92, 122, 0.35); }
.chip.HIGH     { color: var(--high); box-shadow: 0 0 0 1px rgba(255, 162, 77, 0.35), 0 0 10px rgba(255, 162, 77, 0.3); }
.chip.MEDIUM   { color: var(--med);  box-shadow: 0 0 0 1px rgba(255, 214, 92, 0.35), 0 0 10px rgba(255, 214, 92, 0.3); }
.chip.LOW      { color: var(--low);  box-shadow: 0 0 0 1px rgba(92, 230, 166, 0.35), 0 0 10px rgba(92, 230, 166, 0.3); }
.chip.INFO     { color: var(--info); box-shadow: 0 0 0 1px rgba(111, 168, 255, 0.35), 0 0 10px rgba(111, 168, 255, 0.3); }

.empty-state {
  color: var(--neu-ink-dim);
  font-family: 'IBM Plex Sans', sans-serif;
  font-size: 13px;
  padding: 12px 0;
}
```

- [ ] **Step 2: Import theme.css in main.jsx**

Add to the top of `dashboard/web/src/main.jsx`:

```jsx
import './theme.css'
```

- [ ] **Step 3: Wrap App.jsx's markup in the .app shell and verify styling loads**

In `dashboard/web/src/App.jsx`, replace the returned `<div style={{...}}>` wrapper with:

```jsx
  return (
    <div className="app">
      <h1 className="header">SENTINEL IPS v2.0</h1>
      <p className="subheader">Real-Time Security Operations Centre</p>
      <p>Connected: {connected ? 'yes' : 'no'}</p>
      <pre>{data ? JSON.stringify(data.monitor, null, 2) : 'waiting for data...'}</pre>
    </div>
  )
```

Run: `cd dashboard/web && npm run dev` (with `python lab/run_dashboard_dev.py` running in another terminal)
Expected: dark `#1B2130` background, condensed bold "SENTINEL IPS v2.0" header in the correct font (inspect via browser devtools that `Barlow Condensed` is the applied `font-family`, not a fallback), cyan uppercase subheader.

- [ ] **Step 4: Commit**

```bash
git add dashboard/web/src/theme.css dashboard/web/src/main.jsx dashboard/web/src/App.jsx
git commit -m "feat: add neumorphic design tokens (theme.css)"
```

---

### Task 6: KpiRow and SystemHealth components

**Files:**
- Create: `dashboard/web/src/components/KpiRow.jsx`
- Create: `dashboard/web/src/components/SystemHealth.jsx`
- Modify: `dashboard/web/src/App.jsx`

**Interfaces:**
- Consumes: `monitor` object (`current_fps`, `total_attacks`, `total_flows`, `uptime_s` — all from `LiveMonitor.snapshot()`), `unique_ips` (int), `health` object (`cpu_pct`, `ram_pct`, `ram_used_gb`, `ram_total_gb`, `disk_free_gb` — all `number | null`, from `dashboard.server._system_health()`).
- Produces: `<KpiRow monitor={...} uniqueIps={...} />`, `<SystemHealth health={...} />`.

- [ ] **Step 1: Write KpiRow.jsx**

```jsx
export default function KpiRow({ monitor, uniqueIps }) {
  const fps = monitor?.current_fps ?? 0
  const fpsDisplay = fps >= 1000
    ? fps.toLocaleString(undefined, { maximumFractionDigits: 0 })
    : Math.round(fps).toString()
  const uptimeS = monitor?.uptime_s ?? 0
  const uptime = new Date(uptimeS * 1000).toISOString().substring(11, 19)

  const tiles = [
    { lbl: 'Flows/sec', val: fpsDisplay },
    { lbl: 'Total Attacks', val: (monitor?.total_attacks ?? 0).toLocaleString() },
    { lbl: 'Total Flows', val: (monitor?.total_flows ?? 0).toLocaleString() },
    { lbl: 'Unique IPs', val: (uniqueIps ?? 0).toLocaleString() },
    { lbl: 'Uptime', val: uptime },
  ]

  return (
    <div className="kpis">
      {tiles.map((t) => (
        <div className="kpi" key={t.lbl}>
          <div className="lbl">{t.lbl}</div>
          <div className="val">{t.val}</div>
        </div>
      ))}
    </div>
  )
}
```

- [ ] **Step 2: Write SystemHealth.jsx**

```jsx
export default function SystemHealth({ health }) {
  const tiles = [
    { lbl: 'CPU', val: health?.cpu_pct != null ? `${health.cpu_pct.toFixed(1)}%` : '—' },
    {
      lbl: 'RAM',
      val: health?.ram_used_gb != null
        ? `${health.ram_used_gb.toFixed(1)} / ${health.ram_total_gb.toFixed(1)} GB`
        : '—',
    },
    { lbl: 'RAM %', val: health?.ram_pct != null ? `${health.ram_pct.toFixed(1)}%` : '—' },
    { lbl: 'Disk Free', val: health?.disk_free_gb != null ? `${health.disk_free_gb.toFixed(1)} GB` : '—' },
  ]
  return (
    <div className="panel">
      <h3>System Health</h3>
      <div className="kpis">
        {tiles.map((t) => (
          <div className="kpi" key={t.lbl}>
            <div className="lbl">{t.lbl}</div>
            <div className="val">{t.val}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
```

- [ ] **Step 3: Wire both into App.jsx**

Replace `dashboard/web/src/App.jsx` in full:

```jsx
import { useEffect, useState } from 'react'
import { io } from 'socket.io-client'
import KpiRow from './components/KpiRow.jsx'
import SystemHealth from './components/SystemHealth.jsx'

export default function App() {
  const [connected, setConnected] = useState(false)
  const [data, setData] = useState(null)

  useEffect(() => {
    const socket = io()
    socket.on('connect', () => setConnected(true))
    socket.on('disconnect', () => setConnected(false))
    socket.on('dashboard_update', (payload) => setData(payload))
    return () => socket.disconnect()
  }, [])

  const monitor = data?.monitor ?? null

  return (
    <div className="app">
      <h1 className="header">SENTINEL IPS v2.0</h1>
      <p className="subheader">Real-Time Security Operations Centre</p>

      {!connected && <div className="banner-reconnecting">Reconnecting to dashboard server…</div>}

      <KpiRow monitor={monitor} uniqueIps={data?.unique_ips} />
      <SystemHealth health={data?.health} />
    </div>
  )
}
```

- [ ] **Step 4: Manually verify**

Terminal A: `python lab/run_dashboard_dev.py`
Terminal B: `cd dashboard/web && npm run dev`
Open `http://localhost:5173`.
Expected: 5 KPI tiles (Flows/sec, Total Attacks, Total Flows, Unique IPs, Uptime) and a "System Health" panel with 4 tiles (CPU, RAM, RAM %, Disk Free), all rendered as raised neumorphic cards, numbers updating every ~3s. Stop both with Ctrl+C.

- [ ] **Step 5: Commit**

```bash
git add dashboard/web/src/components/KpiRow.jsx dashboard/web/src/components/SystemHealth.jsx dashboard/web/src/App.jsx
git commit -m "feat: add KpiRow and SystemHealth panels"
```

---

### Task 7: ThroughputChart and AlertTable components

**Files:**
- Create: `dashboard/web/src/components/ThroughputChart.jsx`
- Create: `dashboard/web/src/components/AlertTable.jsx`
- Modify: `dashboard/web/src/App.jsx`

**Interfaces:**
- Consumes: `monitor.throughput_fps` (`number[]`), `monitor.events_list` (array of `{time, attack, src_ip, confidence, severity, tactic, risk, action}` — all strings, from `LiveMonitor.DetectionEvent.to_row()`).
- Produces: `<ThroughputChart series={...} />`, `<AlertTable events={...} />`.

- [ ] **Step 1: Write ThroughputChart.jsx**

```jsx
export default function ThroughputChart({ series }) {
  const data = series && series.length > 0 ? series : [0]
  const max = Math.max(...data, 1)
  const min = Math.min(...data, 0)
  const range = max - min || 1
  const w = 400
  const h = 120
  const step = data.length > 1 ? w / (data.length - 1) : 0

  const points = data
    .map((v, i) => {
      const x = i * step
      const y = h - ((v - min) / range) * h
      return `${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')

  const lastX = (data.length - 1) * step
  const lastY = h - ((data[data.length - 1] - min) / range) * h

  return (
    <div className="panel">
      <h3>Live Throughput (flows/sec)</h3>
      <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
        <polyline
          points={points}
          fill="none"
          stroke="#5AD1E6"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <circle cx={lastX} cy={lastY} r="4" fill="#5AD1E6" />
      </svg>
    </div>
  )
}
```

- [ ] **Step 2: Write AlertTable.jsx**

```jsx
export default function AlertTable({ events }) {
  if (!events || events.length === 0) {
    return (
      <div className="panel">
        <h3>Live Alert Stream</h3>
        <p className="empty-state">Waiting for detections…</p>
      </div>
    )
  }
  return (
    <div className="panel">
      <h3>Live Alert Stream</h3>
      <table className="alert-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Attack</th>
            <th>Src IP</th>
            <th>Conf</th>
            <th>Sev</th>
          </tr>
        </thead>
        <tbody>
          {events.slice(0, 20).map((e, i) => (
            <tr key={i}>
              <td>{e.time}</td>
              <td>{e.attack}</td>
              <td>{e.src_ip}</td>
              <td>{e.confidence}</td>
              <td>
                <span className={`chip ${e.severity}`}>{e.severity}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
```

- [ ] **Step 3: Wire both into App.jsx**

In `dashboard/web/src/App.jsx`, add imports:

```jsx
import ThroughputChart from './components/ThroughputChart.jsx'
import AlertTable from './components/AlertTable.jsx'
```

Add this block right after `<KpiRow ... />`:

```jsx
      <div className="grid-2">
        <ThroughputChart series={monitor?.throughput_fps ?? []} />
        <AlertTable events={monitor?.events_list ?? []} />
      </div>
```

- [ ] **Step 4: Manually verify**

Terminal A: `python lab/run_dashboard_dev.py`
Terminal B: `cd dashboard/web && npm run dev`
Open `http://localhost:5173`.
Expected: a two-column row — left: a cyan sparkline trending with the throughput samples; right: a scrolling alert table with coloured severity chips per row (e.g. `CRITICAL` in `--crit` red-pink, `HIGH` in `--high` amber), newest event on top. Stop both with Ctrl+C.

- [ ] **Step 5: Commit**

```bash
git add dashboard/web/src/components/ThroughputChart.jsx dashboard/web/src/components/AlertTable.jsx dashboard/web/src/App.jsx
git commit -m "feat: add ThroughputChart and AlertTable panels"
```

---

### Task 8: PlotlyPanel wrapper and the 5 chart panels — full 9-panel layout

**Files:**
- Create: `dashboard/web/src/components/PlotlyPanel.jsx`
- Create: `dashboard/web/src/components/AttackBarChart.jsx`
- Create: `dashboard/web/src/components/SeverityPie.jsx`
- Create: `dashboard/web/src/components/WorldMap.jsx`
- Create: `dashboard/web/src/components/Choropleth.jsx`
- Create: `dashboard/web/src/components/MitreHeatmap.jsx`
- Modify: `dashboard/web/src/App.jsx`

**Interfaces:**
- Consumes: `data.figures.{world_map,choropleth,mitre_heatmap,attack_bar,severity_pie}` — each either `null` or a Plotly figure dict `{data: [...], layout: {...}}` (from Task 2's `_figure_to_json`).
- Produces: `<PlotlyPanel title={...} figure={...} />` and 5 thin wrappers around it.

- [ ] **Step 1: Write PlotlyPanel.jsx**

```jsx
import createPlotlyComponent from 'react-plotly.js/factory'
import Plotly from 'plotly.js-dist-min'

const Plot = createPlotlyComponent(Plotly)

export default function PlotlyPanel({ title, figure }) {
  if (!figure) {
    return (
      <div className="panel">
        <h3>{title}</h3>
        <p className="empty-state">No data yet.</p>
      </div>
    )
  }
  return (
    <div className="panel">
      <h3>{title}</h3>
      <Plot
        data={figure.data}
        layout={{ ...figure.layout, autosize: true, margin: { l: 10, r: 10, t: 10, b: 10 } }}
        style={{ width: '100%', height: '320px' }}
        useResizeHandler
        config={{ displayModeBar: false, responsive: true }}
      />
    </div>
  )
}
```

- [ ] **Step 2: Write the 5 thin wrapper components**

`dashboard/web/src/components/AttackBarChart.jsx`:
```jsx
import PlotlyPanel from './PlotlyPanel.jsx'

export default function AttackBarChart({ figure }) {
  return <PlotlyPanel title="Attack Type Distribution" figure={figure} />
}
```

`dashboard/web/src/components/SeverityPie.jsx`:
```jsx
import PlotlyPanel from './PlotlyPanel.jsx'

export default function SeverityPie({ figure }) {
  return <PlotlyPanel title="Severity Breakdown" figure={figure} />
}
```

`dashboard/web/src/components/WorldMap.jsx`:
```jsx
import PlotlyPanel from './PlotlyPanel.jsx'

export default function WorldMap({ figure }) {
  return <PlotlyPanel title="World Attack Map — Live Origins" figure={figure} />
}
```

`dashboard/web/src/components/Choropleth.jsx`:
```jsx
import PlotlyPanel from './PlotlyPanel.jsx'

export default function Choropleth({ figure }) {
  return <PlotlyPanel title="Attack Volume by Country" figure={figure} />
}
```

`dashboard/web/src/components/MitreHeatmap.jsx`:
```jsx
import PlotlyPanel from './PlotlyPanel.jsx'

export default function MitreHeatmap({ figure }) {
  return <PlotlyPanel title="MITRE ATT&CK Coverage Matrix" figure={figure} />
}
```

- [ ] **Step 3: Assemble the full 9-panel App.jsx**

Replace `dashboard/web/src/App.jsx` in full:

```jsx
import { useEffect, useState } from 'react'
import { io } from 'socket.io-client'
import KpiRow from './components/KpiRow.jsx'
import SystemHealth from './components/SystemHealth.jsx'
import ThroughputChart from './components/ThroughputChart.jsx'
import AlertTable from './components/AlertTable.jsx'
import AttackBarChart from './components/AttackBarChart.jsx'
import SeverityPie from './components/SeverityPie.jsx'
import WorldMap from './components/WorldMap.jsx'
import Choropleth from './components/Choropleth.jsx'
import MitreHeatmap from './components/MitreHeatmap.jsx'

export default function App() {
  const [connected, setConnected] = useState(false)
  const [data, setData] = useState(null)

  useEffect(() => {
    const socket = io()
    socket.on('connect', () => setConnected(true))
    socket.on('disconnect', () => setConnected(false))
    socket.on('dashboard_update', (payload) => setData(payload))
    return () => socket.disconnect()
  }, [])

  const monitor = data?.monitor ?? null
  const figures = data?.figures ?? {}

  return (
    <div className="app">
      <h1 className="header">SENTINEL IPS v2.0</h1>
      <p className="subheader">Real-Time Security Operations Centre</p>

      {!connected && <div className="banner-reconnecting">Reconnecting to dashboard server…</div>}

      <KpiRow monitor={monitor} uniqueIps={data?.unique_ips} />

      <div className="grid-2">
        <ThroughputChart series={monitor?.throughput_fps ?? []} />
        <AlertTable events={monitor?.events_list ?? []} />
      </div>

      <div className="grid-2">
        <AttackBarChart figure={figures.attack_bar} />
        <SeverityPie figure={figures.severity_pie} />
      </div>

      <WorldMap figure={figures.world_map} />
      <Choropleth figure={figures.choropleth} />
      <MitreHeatmap figure={figures.mitre_heatmap} />
      <SystemHealth health={data?.health} />
    </div>
  )
}
```

- [ ] **Step 4: Manually verify all 9 panels render**

Terminal A: `python lab/run_dashboard_dev.py`
Terminal B: `cd dashboard/web && npm run dev`
Open `http://localhost:5173`.
Expected: all 9 panels visible and updating — KPI row, throughput sparkline, alert table, attack bar chart, severity pie, world map (bubbles over the sample countries), choropleth, MITRE heatmap, system health. Open the browser console and confirm no errors. Stop both with Ctrl+C.

- [ ] **Step 5: Commit**

```bash
git add dashboard/web/src/components/PlotlyPanel.jsx dashboard/web/src/components/AttackBarChart.jsx dashboard/web/src/components/SeverityPie.jsx dashboard/web/src/components/WorldMap.jsx dashboard/web/src/components/Choropleth.jsx dashboard/web/src/components/MitreHeatmap.jsx dashboard/web/src/App.jsx
git commit -m "feat: complete the 9-panel neumorphic dashboard layout"
```

---

### Task 9: Production build and Flask static serving — final end-to-end verification

**Files:**
- None created/modified (build output only — `dashboard/web/dist/` is a build artifact; confirm it's covered by `.gitignore` in Step 1).

- [ ] **Step 1: Ensure the build output is gitignored**

Check `.gitignore` for a `dist/` or `dashboard/web/dist/` entry. If missing, add:

```
dashboard/web/dist/
dashboard/web/node_modules/
```

- [ ] **Step 2: Build the frontend**

```bash
cd dashboard/web
npm run build
```

Expected: `dashboard/web/dist/index.html` and a `dashboard/web/dist/assets/` directory now exist, build completes with no errors.

- [ ] **Step 3: Confirm Flask serves the built app directly (no Vite dev server)**

```bash
python lab/run_dashboard_dev.py
```

Open `http://localhost:5000` directly in a browser (not 5173 — no Vite this time).
Expected: the full 9-panel dashboard renders identically to the dev-mode version, served entirely from Flask on a single origin. Stop with Ctrl+C.

- [ ] **Step 4: Full end-to-end verification against the real pipeline**

```bash
python sentinel.py health
python sentinel.py simulate --sample 0.001
```

Expected: both exit 0. `simulate` mode doesn't start the dashboard server (only `_run_live()` does, per Task 3) — this step only confirms the rest of the pipeline is undisturbed by this feature's changes.

If a live capture environment (Npcap + lab VMs, per `docs/SESSION_LEDGER.md`'s prior lab sessions) is available, additionally run:
```bash
python sentinel.py live --interface <lab-interface>
```
and open `http://localhost:5000` to confirm real detections appear (not required to close out this plan if the lab network isn't set up in this session — the dev harness in Steps 2-3 already proves the full stack end-to-end against synthetic data structurally identical to what `sentinel.py live` produces).

- [ ] **Step 5: Commit**

```bash
git add .gitignore
git commit -m "chore: gitignore dashboard frontend build output"
```
