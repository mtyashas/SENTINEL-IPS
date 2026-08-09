# Live Dashboard — Design Spec

**Date:** 2026-08-09
**Status:** Approved, ready for implementation planning

## Problem

`dashboard/app.py` (Streamlit) is not actually live. `sentinel.py` creates its
own `LiveMonitor()` instance inside its own process
(`sentinel.py:256`); the Streamlit dashboard creates a separate
`LiveMonitor()` bound to Streamlit's per-browser-session state
(`dashboard/app.py:61`, `get_monitor()`). These are two different Python
processes with separate memory — nothing wires them together — which is why
`app.py` has to fall back to injecting synthetic demo events
(`_inject_demo_events`) to have anything to show.

This spec replaces the Streamlit dashboard with a dashboard that shows real
`sentinel.py live` data, no synthetic fallback.

## Scope

Full replacement of `dashboard/app.py` as the SOC monitor. The old Streamlit
files (`app.py`, and the data-layer modules it currently drives) stay in the
repo unused — not deleted, not maintained.

Out of scope: simulate/demo mode for the new dashboard (live-only, per
decision below), authentication (matches the old dashboard's no-auth
posture — this is a local lab tool), multi-user/remote deployment.

## Architecture

Single process. `sentinel.py live` starts the detection pipeline *and* an
embedded dashboard server, sharing the same in-memory objects directly — no
IPC, no file/DB polling.

```
sentinel.py (live mode)
  ├── existing detection pipeline (Layer1/2/3, response, adaptive, etc.)
  ├── self._monitor = LiveMonitor()     [reused unchanged]
  ├── self._amap    = AttackMap()       [reused unchanged]
  └── dashboard/server.py: start_dashboard_server(monitor, amap)
        → Flask + Flask-SocketIO app, run in a background thread
        → background emitter thread, every ~2s:
            snapshot = monitor.snapshot()
            figures  = amap.scatter_geo_figure(), amap.choropleth_figure(),
                       mitre heatmap (built from snapshot["attack_counts"])
            health   = psutil CPU/RAM/disk
            socketio.emit("dashboard_update", {snapshot, figures, health})
        → also emits immediately on push_event() for low-latency alerts
        → serves the built React app's static files (dist/) at "/"
```

This was chosen over a separate-process + shared-store design (file/SQLite/
Redis) because it needs zero new infrastructure and reuses `LiveMonitor`/
`AttackMap` exactly as they are — the tradeoff (dashboard restart requires a
detection-pipeline restart) was accepted as acceptable for a local lab tool.

`sentinel.py live` auto-starts the dashboard server; there's no separate
`--dashboard` flag, since without live detection running there's nothing
live to show.

## Key simplification: reuse Plotly figures as JSON

`dashboard/attack_map.py`'s `scatter_geo_figure()`, `choropleth_figure()`,
and the MITRE-heatmap-building logic (currently inline in
`dashboard/app.py`, panel 8) already produce Plotly figure objects in
Python. Rather than reimplementing world-map/choropleth/heatmap chart logic
in JS, the backend serializes them with `fig.to_json()` and the frontend
renders them with `react-plotly.js`'s `<Plot data={...} layout={...}/>`.
This means only the KPI tiles, alert table, and throughput sparkline are
genuinely custom React components — every geo/heatmap panel is a thin
Plotly-JSON pass-through with zero duplicated chart logic.

The reused Plotly figures get a dark template override (`paper_bgcolor`/
`plot_bgcolor` set to the neumorphic base tone, font colours matching the
neumorphic ink tones) so they read as part of the same surface instead of
Plotly's white-chrome defaults.

## Backend

- **Framework:** Flask + Flask-SocketIO. Flask is already a project
  dependency (`requirements.txt`); `flask-socketio` is a new addition.
  Chosen over FastAPI to avoid a second web framework in the project for no
  functional gain here.
- **New file:** `dashboard/server.py` — owns the Flask app, the SocketIO
  instance, the background emitter thread, and static-file serving of the
  built frontend. Exposes `start_dashboard_server(monitor: LiveMonitor,
  amap: AttackMap, host, port) -> None`, called from `sentinel.py`'s
  `_run_live()`.
- **Reused unchanged:** `dashboard/live_monitor.py`, `dashboard/attack_map.py`.
- **Wire protocol:** one Socket.IO event, `dashboard_update`, carrying the
  full snapshot payload (KPIs, throughput series, alert rows, attack/severity
  counts, the three serialized Plotly figures, system health). No REST
  polling endpoints needed for live data; a plain `GET /` (and static asset
  routes) serves the built React app.

## Frontend

- **Stack:** React + Vite, new `dashboard/web/` directory.
- **Dev workflow:** `npm run dev` (Vite on 5173) proxies API/socket traffic
  to Flask on 5000. Ship/demo workflow: `npm run build` → Flask serves
  `dist/` directly from a single URL, no CORS configuration needed.
- **State:** one `socket.io-client` connection, one `onDashboardUpdate`
  handler feeding top-level React state; panels are pure render components
  off that state.
- **Components (9 panels, matching the old dashboard's feature set):**
  `KpiRow`, `ThroughputChart`, `AlertTable`, `AttackBarChart`, `SeverityPie`,
  `WorldMap`, `Choropleth`, `MitreHeatmap`, `SystemHealth`. The last five are
  thin `<PlotlyPanel figure={...}/>` wrappers around `react-plotly.js`;
  `KpiRow`, `AlertTable`, and `ThroughputChart` are custom components.

## Visual design — Neumorphic SOC

Chosen after a side-by-side mockup comparison against a flat-dark-SOC
baseline (both rendered with identical sample data). Neumorphism was picked
over the flat baseline specifically for this dashboard's "quiet until
something matters" character — chrome recedes into soft shadow, severity
chips are the one thing that visibly pops.

**Color tokens:**

| Token | Hex | Use |
|---|---|---|
| `--neu-base` | `#1B2130` | page + card surface (cards are cut from the same tone as the page) |
| `--neu-light` | `#262E42` | raised-shadow highlight tint |
| `--neu-dark` | `#10141D` | raised-shadow / pressed-well shadow tint |
| `--neu-accent` | `#5AD1E6` | sparing use only — active states, chart lines, icons |
| `--neu-ink` | `#EAF0FA` | primary text |
| `--neu-ink-dim` | `#8996AD` | secondary/label text |

Severity is a **separate** semantic set, independent of the accent color, so
alert meaning is never confused with brand/interactive color:

| Severity | Hex |
|---|---|
| Critical | `#FF5C7A` |
| High | `#FFA24D` |
| Medium | `#FFD65C` |
| Low | `#5CE6A6` |
| Info | `#6FA8FF` |

**Typography:** Barlow Condensed (700/900) for headers and large KPI
numbers; IBM Plex Sans (400/600) for UI text/labels; IBM Plex Mono (400/500)
for data — IPs, timestamps, confidence percentages, counts — set with
`font-variant-numeric: tabular-nums` wherever digits line up in columns.

**Shape/depth language:** cards are the same surface color as the page
background; depth comes from a dual soft box-shadow (light source top-left:
`--neu-light` highlight, `--neu-dark` shadow), not borders. Generous 18–22px
corner radii. Read-out panels (alert table, throughput chart) use an
*inset* shadow ("pressed into" the surface) to visually distinguish
data-display panels from raised interactive elements (KPI tiles, buttons).

**Known risk, and how it's countered:** neumorphism's classic failure mode
is low card/background contrast eating legibility. This is countered by
keeping **text** (`--neu-ink` against `--neu-base` is a real, checked
contrast ratio, not just a shadow illusion) and **severity chips**
(rendered as a colored glow + colored text, not a shadow-only surface) on
their own independent contrast — so an alert reads at a glance even though
the surrounding chrome is deliberately quiet.

## Error handling

- **Socket disconnect:** frontend shows a "reconnecting…" banner;
  `socket.io-client`'s built-in reconnection/backoff handles the retry —
  no custom reconnect logic needed.
- **Cold start / no events yet:** KPIs render `0`/`—`, alert table renders
  an explicit "waiting for detections…" empty state rather than a blank
  table.
- **Emitter tick failure:** if building one snapshot throws (e.g. a bad
  Plotly figure), the emitter thread logs the exception and skips that
  tick rather than dying — one bad tick must not silently kill the live
  feed for the rest of the session.

## Testing

- **Primary verification:** manual end-to-end via `sentinel.py live`
  against the existing lab setup (same verification approach used for every
  other module in this project — see `docs/SESSION_LEDGER.md`).
- **One automated check:** the emitter thread's full snapshot payload
  (LiveMonitor snapshot + the three serialized Plotly figures + health)
  round-trips cleanly through `json.dumps`/`json.loads` — this is the one
  place a silent serialization break (e.g. a non-JSON-safe value leaking
  into a Plotly figure or a NaN in a numpy-derived stat) could hide
  undetected behind a working-looking UI.

## File structure changes

```
dashboard/
├── __init__.py            [unchanged]
├── app.py                 [unchanged, unused]
├── live_monitor.py        [unchanged, reused]
├── attack_map.py          [unchanged, reused]
├── server.py               NEW — Flask + Flask-SocketIO app, emitter thread
└── web/                     NEW — Vite + React frontend
    ├── package.json
    ├── index.html
    ├── vite.config.js
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── theme.css        neumorphic design tokens
        └── components/
            ├── KpiRow.jsx
            ├── ThroughputChart.jsx
            ├── AlertTable.jsx
            ├── PlotlyPanel.jsx
            ├── AttackBarChart.jsx
            ├── SeverityPie.jsx
            ├── WorldMap.jsx
            ├── Choropleth.jsx
            ├── MitreHeatmap.jsx
            └── SystemHealth.jsx

sentinel.py                 MODIFIED — _run_live() calls
                             dashboard.server.start_dashboard_server(...)

requirements.txt             MODIFIED — add flask-socketio
```
