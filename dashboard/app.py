"""
dashboard/app.py

Purpose: SENTINEL IPS v2.0 real-time monitoring dashboard built on Streamlit.
         Renders nine panels in a dark-themed SOC-style layout:
           1. System health KPIs (flows/sec, total attacks, uptime)
           2. Live throughput sparkline
           3. Scrolling alert table with severity colour coding
           4. Attack-type distribution bar chart
           5. Severity distribution pie chart
           6. World attack map (scatter-geo bubble map)
           7. Choropleth heatmap (attack volume by country)
           8. MITRE ATT&CK technique coverage heatmap
           9. System health monitor (CPU / RAM gauges via psutil)

         Run with:
             streamlit run dashboard/app.py

         The dashboard auto-refreshes every REFRESH_INTERVAL_S seconds using
         st.rerun() after sleeping, so it works without a live sentinel.py
         process.  When sentinel.py is running, it writes events to the shared
         LiveMonitor instance via the dashboard.get_monitor() accessor.

Inputs:  LiveMonitor singleton (in-memory); optional AttackMap singleton.
Outputs: Rendered Streamlit page.
"""

import sys
import time
from pathlib import Path

# Ensure project root is on sys.path when launched from any directory
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st

from config import MITRE_ATTACK_MAP, SEVERITY_LEVELS
from dashboard.attack_map import AttackMap
from dashboard.live_monitor import SEVERITY_COLOURS, LiveMonitor

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REFRESH_INTERVAL_S = 3          # seconds between auto-refreshes
PAGE_TITLE         = "SENTINEL IPS v2.0 — SOC Dashboard"
_DARK_BG           = "#0D1117"
_PANEL_BG          = "#161B22"
_ACCENT            = "#58A6FF"

# ---------------------------------------------------------------------------
# Singleton accessors — stored in st.session_state so they survive reruns.
# sentinel.py imports these functions to push events into the live dashboard.
# ---------------------------------------------------------------------------

def get_monitor() -> LiveMonitor:
    """Return the shared LiveMonitor singleton (persisted in session state)."""
    if "sentinel_monitor" not in st.session_state:
        st.session_state["sentinel_monitor"] = LiveMonitor()
    return st.session_state["sentinel_monitor"]


def get_attack_map() -> AttackMap:
    """Return the shared AttackMap singleton (persisted in session state)."""
    if "sentinel_amap" not in st.session_state:
        st.session_state["sentinel_amap"] = AttackMap()
    return st.session_state["sentinel_amap"]


# ---------------------------------------------------------------------------
# Demo data injection (used when no live sentinel process is attached)
# ---------------------------------------------------------------------------

def _inject_demo_events(monitor: LiveMonitor, amap: AttackMap, n: int = 8) -> None:
    """Populate the monitor with synthetic events for demonstration."""
    import random
    import math

    attacks = [
        ("DDoS",        "HIGH",     "Impact",            "203.0.113.10", "US", "USA", 37.09, -95.71),
        ("PortScan",    "LOW",      "Discovery",         "198.51.100.5", "RU", "RUS", 61.52, 105.31),
        ("BruteForce",  "MEDIUM",   "Initial Access",    "192.0.2.88",   "CN", "CHN", 35.86, 104.19),
        ("Bot",         "HIGH",     "Persistence",       "185.220.101.5","DE", "DEU", 51.16, 10.45),
        ("SQLInjection","MEDIUM",   "Execution",         "203.0.113.77", "BR", "BRA", -14.23, -51.92),
        ("Infiltration","CRITICAL", "Lateral Movement",  "198.51.100.42","KP", "PRK", 40.33, 127.51),
        ("ZeroDay",     "CRITICAL", "Multiple",          "192.0.2.200",  "IR", "IRN", 32.42, 53.68),
        ("Heartbleed",  "CRITICAL", "Defense Evasion",   "203.0.113.51", "NG", "NGA", 9.08, 8.68),
        ("XSS",         "MEDIUM",   "Execution",         "198.51.100.99","IN", "IND", 20.59, 78.96),
        ("DoS",         "HIGH",     "Impact",            "192.0.2.15",   "RO", "ROU", 45.94, 24.96),
    ]

    rng = random.Random(int(time.time()) % 1000)
    for i in range(n):
        a = attacks[i % len(attacks)]
        event = {
            "attack_type":  a[0],
            "severity":     a[1],
            "mitre_tactic": a[2],
            "src_ip":       a[3],
            "confidence":   round(rng.uniform(0.65, 0.99), 3),
            "risk_score":   round(rng.uniform(30, 98), 1),
            "action":       "ip_block",
            "lat":          a[6] + rng.uniform(-2, 2),
            "lon":          a[7] + rng.uniform(-2, 2),
            "country":      a[4],
            "country_code": a[5],
            "city":         "Unknown",
        }
        monitor.push_event(event)
        amap.ingest(event)

    for _ in range(20):
        monitor.record_throughput(round(rng.uniform(800_000, 1_700_000), 0))
    monitor.increment_flows(rng.randint(50_000, 200_000))


# ---------------------------------------------------------------------------
# Page config (must be first Streamlit call)
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title=PAGE_TITLE,
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Custom CSS — dark SOC theme
# ---------------------------------------------------------------------------

st.markdown(f"""
<style>
  /* Global dark background */
  .stApp {{ background-color: {_DARK_BG}; color: #E0E0E0; }}
  /* Metric boxes */
  [data-testid="metric-container"] {{
      background-color: {_PANEL_BG};
      border: 1px solid #30363D;
      border-radius: 8px;
      padding: 12px 16px;
  }}
  /* Section headers */
  .sentinel-header {{
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 1.2px;
      color: {_ACCENT};
      text-transform: uppercase;
      margin-bottom: 6px;
      border-bottom: 1px solid #30363D;
      padding-bottom: 4px;
  }}
  /* Alert table rows by severity */
  .sev-CRITICAL {{ color: #E53935; font-weight: bold; }}
  .sev-HIGH     {{ color: #FB8C00; font-weight: bold; }}
  .sev-MEDIUM   {{ color: #FDD835; }}
  .sev-LOW      {{ color: #43A047; }}
  .sev-INFO     {{ color: #29B6F6; }}
  /* Scrollable table container */
  .alert-scroll {{
      max-height: 280px;
      overflow-y: auto;
      font-size: 12px;
  }}
  /* Remove default Streamlit padding on the main block */
  .block-container {{ padding-top: 1rem; padding-bottom: 1rem; }}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

monitor = get_monitor()
amap    = get_attack_map()

# Session state: inject demo data once per session if monitor is empty
if "demo_injected" not in st.session_state:
    st.session_state["demo_injected"] = False

snap = monitor.snapshot()
if not st.session_state["demo_injected"]:
    _inject_demo_events(monitor, amap, n=40)
    st.session_state["demo_injected"] = True
    snap = monitor.snapshot()
elif snap["total_attacks"] < 5:
    # session state was reset (e.g. new browser tab) — reinject
    _inject_demo_events(monitor, amap, n=40)
    snap = monitor.snapshot()

# ---------------------------------------------------------------------------
# Header bar
# ---------------------------------------------------------------------------

st.markdown(
    f"<h2 style='color:{_ACCENT}; margin:0; font-family:monospace;'>"
    f"🛡 SENTINEL IPS v2.0 &nbsp;|&nbsp; "
    f"<span style='font-size:14px; color:#8B949E;'>Real-Time Security Operations Centre</span>"
    f"</h2>",
    unsafe_allow_html=True,
)
st.markdown("<hr style='border-color:#30363D; margin:6px 0 14px 0;'>",
            unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Panel 1 — KPI metrics row
# ---------------------------------------------------------------------------

st.markdown("<div class='sentinel-header'>System Status</div>",
            unsafe_allow_html=True)

k1, k2, k3, k4, k5 = st.columns(5)
uptime_str = time.strftime("%H:%M:%S", time.gmtime(snap["uptime_s"]))
fps        = snap["current_fps"]
fps_str    = f"{fps:,.0f}" if fps >= 1000 else f"{fps:.0f}"

k1.metric("Flows / sec",     fps_str)
k2.metric("Total Attacks",   f"{snap['total_attacks']:,}")
k3.metric("Total Flows",     f"{snap['total_flows']:,}")
k4.metric("Unique IPs",      f"{amap.total_unique_ips():,}")
k5.metric("Uptime",          uptime_str)

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Panel 2 — Throughput sparkline + Panel 3 — Alert table
# ---------------------------------------------------------------------------

col_tput, col_alerts = st.columns([1, 2])

with col_tput:
    st.markdown("<div class='sentinel-header'>Live Throughput (flows/sec)</div>",
                unsafe_allow_html=True)
    tput_data = snap["throughput_fps"]
    if tput_data:
        import pandas as pd
        tput_df = pd.DataFrame({"fps": tput_data})
        st.line_chart(tput_df, y="fps", width="stretch", height=200)
    else:
        st.info("Waiting for throughput data...")

with col_alerts:
    st.markdown("<div class='sentinel-header'>Live Alert Stream</div>",
                unsafe_allow_html=True)
    events = snap["events_list"]
    if events:
        import pandas as pd
        df_alerts = pd.DataFrame(events)
        st.dataframe(
            df_alerts,
            width="stretch",
            height=220,
            hide_index=True,
        )
    else:
        st.info("No alerts yet. Waiting for detection events...")

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Panel 4 — Attack distribution + Panel 5 — Severity breakdown
# ---------------------------------------------------------------------------

col_bar, col_pie = st.columns([3, 2])

with col_bar:
    st.markdown("<div class='sentinel-header'>Attack Type Distribution</div>",
                unsafe_allow_html=True)
    attack_counts = snap["attack_counts"]
    if attack_counts:
        import pandas as pd
        import plotly.express as px
        df_atk = pd.DataFrame(
            sorted(attack_counts.items(), key=lambda x: x[1], reverse=True),
            columns=["Attack Type", "Count"],
        )
        fig_bar = px.bar(
            df_atk, x="Count", y="Attack Type", orientation="h",
            color="Count",
            color_continuous_scale="Reds",
            template="plotly_dark",
            height=300,
        )
        fig_bar.update_layout(
            paper_bgcolor=_PANEL_BG, plot_bgcolor=_PANEL_BG,
            showlegend=False,
            coloraxis_showscale=False,
            margin=dict(l=0, r=10, t=10, b=0),
            yaxis=dict(autorange="reversed"),
        )
        st.plotly_chart(fig_bar, width="stretch")
    else:
        st.info("No attack data yet.")

with col_pie:
    st.markdown("<div class='sentinel-header'>Severity Breakdown</div>",
                unsafe_allow_html=True)
    sev_counts = snap["severity_counts"]
    if sev_counts:
        import plotly.graph_objects as go
        labels = list(sev_counts.keys())
        values = list(sev_counts.values())
        colours = [SEVERITY_COLOURS.get(s, "#78909C") for s in labels]
        fig_pie = go.Figure(go.Pie(
            labels=labels, values=values,
            marker=dict(colors=colours),
            textinfo="label+percent",
            hole=0.4,
        ))
        fig_pie.update_layout(
            paper_bgcolor=_PANEL_BG,
            font=dict(color="#E0E0E0"),
            margin=dict(l=0, r=0, t=10, b=0),
            height=300,
            showlegend=True,
            legend=dict(font=dict(color="#E0E0E0"), bgcolor=_PANEL_BG),
        )
        st.plotly_chart(fig_pie, width="stretch")
    else:
        st.info("No severity data yet.")

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Panel 6 — World attack scatter map
# ---------------------------------------------------------------------------

st.markdown("<div class='sentinel-header'>World Attack Map — Live Origins</div>",
            unsafe_allow_html=True)
fig_scatter = amap.scatter_geo_figure()
if fig_scatter is not None:
    st.plotly_chart(fig_scatter, width="stretch")
else:
    st.warning("plotly not installed — run: pip install plotly")

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Panel 7 — Choropleth heatmap
# ---------------------------------------------------------------------------

col_choro, col_top = st.columns([3, 1])

with col_choro:
    st.markdown("<div class='sentinel-header'>Attack Volume by Country</div>",
                unsafe_allow_html=True)
    fig_choro = amap.choropleth_figure()
    if fig_choro is not None:
        st.plotly_chart(fig_choro, width="stretch")

with col_top:
    st.markdown("<div class='sentinel-header'>Top Attack Origins</div>",
                unsafe_allow_html=True)
    top_c = amap.top_countries(10)
    if top_c:
        import pandas as pd
        df_top = pd.DataFrame(top_c, columns=["Country", "Attacks"])
        st.dataframe(df_top, width="stretch", hide_index=True, height=300)
    else:
        st.info("No geo data yet.")

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Panel 8 — MITRE ATT&CK coverage heatmap
# ---------------------------------------------------------------------------

st.markdown("<div class='sentinel-header'>MITRE ATT&CK Coverage Matrix</div>",
            unsafe_allow_html=True)

_TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact", "Multiple",
]

_TACTIC_ABBR = {t: t[:8] for t in _TACTIC_ORDER}

try:
    import plotly.graph_objects as go
    import pandas as pd

    attack_counts_now = snap["attack_counts"]
    mitre_rows: dict[str, dict[str, int]] = {}

    for attack, meta in MITRE_ATTACK_MAP.items():
        tactic    = meta.get("tactic",    "Unknown")
        technique = meta.get("technique", "T0000")
        count     = attack_counts_now.get(attack, 0)
        if tactic not in mitre_rows:
            mitre_rows[tactic] = {}
        mitre_rows[tactic][f"{technique}\n{attack}"] = count

    if mitre_rows:
        tactics    = [t for t in _TACTIC_ORDER if t in mitre_rows]
        techniques = sorted({tech for row in mitre_rows.values() for tech in row})

        z_matrix = []
        for tactic in tactics:
            row = [mitre_rows[tactic].get(tech, 0) for tech in techniques]
            z_matrix.append(row)

        fig_mitre = go.Figure(go.Heatmap(
            z=z_matrix,
            x=techniques,
            y=tactics,
            colorscale="YlOrRd",
            showscale=True,
            hovertemplate="Tactic: %{y}<br>Technique: %{x}<br>Count: %{z}<extra></extra>",
            colorbar=dict(
                title=dict(text="Detections", font=dict(color="#E0E0E0")),
                tickfont=dict(color="#E0E0E0"),
            ),
        ))
        fig_mitre.update_layout(
            paper_bgcolor=_PANEL_BG,
            plot_bgcolor=_PANEL_BG,
            font=dict(color="#E0E0E0", size=10),
            xaxis=dict(tickangle=-45, tickfont=dict(size=9)),
            yaxis=dict(tickfont=dict(size=10)),
            margin=dict(l=10, r=10, t=10, b=80),
            height=320,
        )
        st.plotly_chart(fig_mitre, width="stretch")
    else:
        st.info("No MITRE data available yet.")
except ImportError:
    st.warning("plotly required for MITRE heatmap.")

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Panel 9 — System health monitor
# ---------------------------------------------------------------------------

st.markdown("<div class='sentinel-header'>System Health</div>",
            unsafe_allow_html=True)

h1, h2, h3, h4 = st.columns(4)

try:
    import psutil
    cpu   = psutil.cpu_percent(interval=None)
    ram   = psutil.virtual_memory()
    ram_p = ram.percent
    ram_u = ram.used  / (1024 ** 3)
    ram_t = ram.total / (1024 ** 3)

    h1.metric("CPU Usage",     f"{cpu:.1f}%",
              delta=None if cpu < 80 else "HIGH")
    h2.metric("RAM Used",      f"{ram_u:.1f} / {ram_t:.1f} GB")
    h3.metric("RAM %",         f"{ram_p:.1f}%",
              delta=None if ram_p < 85 else "HIGH")
    try:
        disk = psutil.disk_usage("/")
        h4.metric("Disk Free", f"{disk.free / (1024**3):.1f} GB")
    except Exception:
        h4.metric("Disk", "N/A")

except ImportError:
    h1.metric("CPU", "psutil required")
    h2.metric("RAM", "psutil required")
    h3.metric("Disk", "psutil required")
    h4.metric("Net", "psutil required")

# ---------------------------------------------------------------------------
# Footer + auto-refresh
# ---------------------------------------------------------------------------

st.markdown("<hr style='border-color:#30363D; margin:18px 0 4px 0;'>",
            unsafe_allow_html=True)
st.markdown(
    "<p style='text-align:center; color:#484F58; font-size:11px;'>"
    "SENTINEL IPS v2.0 &nbsp;|&nbsp; CyberCore Intelligence &nbsp;|&nbsp; "
    "Project P52 &nbsp;|&nbsp; "
    f"Refresh every {REFRESH_INTERVAL_S}s"
    "</p>",
    unsafe_allow_html=True,
)

# Auto-refresh: sleep then rerun
time.sleep(REFRESH_INTERVAL_S)
st.rerun()
