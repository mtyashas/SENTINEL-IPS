# Session Ledger

A running, dated record of what happened in each working session on
SENTINEL IPS, so the project owner (and any teammate) can re-orient
quickly without re-reading chat history or `git log`. Newest entry on
top. An entry is written only when the user says a stop phrase ("stop
session", "end session", "wrap up") after opting in at the start of that
session — see `docs/superpowers/specs/2026-07-21-session-ledger-design.md`
for the full protocol.

---

## 2026-07-22 — Session ledger bootstrap + live-capture lab M1 (Kali side)

**Goal:** Pick up the in-progress live-traffic validation lab from the
previous session (VirtualBox lab validating `core/flow_collector.py` and
`sentinel.py live` against real packets) and work through the M1-M5
milestone runbook in `lab/README.md`, starting with M1 (network
reachability). Also build the session ledger feature itself, since it had
been designed (`docs/superpowers/specs/2026-07-21-session-ledger-design.md`)
but never implemented.

**Changes:**
- Added the "SESSION LEDGER PROTOCOL" section to `CLAUDE.md` (ask at
  session start, track silently, record on stop phrase) and bootstrapped
  this file, `docs/SESSION_LEDGER.md`.
- Confirmed prior session's live-capture work was already in place but
  uncommitted: `core/flow_collector.py` (504 lines), `sentinel.py live`
  rewired to use it, `config.py` live-capture constants, and the
  `lab/` directory (README + `target_service.py`) — all still unstaged.
- Verified the Windows host's VirtualBox Host-Only adapter exists and is up.
- Found the Kali attacker VM (`kali-linux-2026.1-virtualbox-amd64`) had only
  a NAT adapter attached, no host-only adapter.
- User attached the host-only network to Kali's second adapter and set a
  static IP via `nmcli` on "Wired connection 2":
  `192.168.56.10/24`, replacing the DHCP-assigned `192.168.56.101`.
- Verified M1 connectivity for Kali in both directions: host → Kali
  (`ping 192.168.56.10`) and Kali → host (`ping 192.168.56.1`), both clean,
  0% packet loss.

**Decisions:**
- Ledger entries are written only on an explicit stop phrase, never
  automatically — user opted in at the start of this session.
- Static IP was set via `nmcli con mod` on the NetworkManager connection
  object (not `/etc/network/interfaces`), since Kali defaults to
  NetworkManager-managed networking.
- Physical adapter slot doesn't matter as long as one adapter is NAT and
  one is host-only — Kali ended up with NAT on nic1 and host-only on nic2,
  opposite of the README's illustrative numbering, and that's fine.
- The benign-traffic VM doesn't need to be Kali — any lightweight
  Debian/Ubuntu image is acceptable.

**Next steps:**
- Create the benign-traffic VM: host-only + NAT adapters, static IP
  `192.168.56.20/24` via the same `nmcli` recipe used for Kali.
- Finish M1 by confirming host ↔ benign-VM ping in both directions.
- Proceed to M2 (packet capture smoke test via
  `forensics.packet_logger.start_live_capture`), then M3 (single-flow
  verification with `lab/target_service.py` + `core/flow_collector.py`),
  M4 (single attack type via `sentinel.py live`), M5 (mixed concurrent
  benign + attack end-to-end).
- Decide when to commit the still-uncommitted changes (`CLAUDE.md`,
  `README.md`, `config.py`, `sentinel.py`, `threat_intel/*.jsonl`,
  `core/flow_collector.py`, `lab/`, `docs/SESSION_LEDGER.md`, the session
  ledger spec) — nothing was committed this session.

---
