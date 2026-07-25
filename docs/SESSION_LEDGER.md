# Session Ledger

A running, dated record of what happened in each working session on
SENTINEL IPS, so the project owner (and any teammate) can re-orient
quickly without re-reading chat history or `git log`. Newest entry on
top. An entry is written only when the user says a stop phrase ("stop
session", "end session", "wrap up") after opting in at the start of that
session — see `docs/superpowers/specs/2026-07-21-session-ledger-design.md`
for the full protocol.

---

## 2026-07-22 — Benign VM stood up; lab M1-M3 complete; two live-capture bugs fixed

**Goal:** Get the benign-traffic VM working and finish M1, then push through
M2 and M3 of the live-traffic validation lab (`lab/README.md`).

**Changes:**
- Fixed the Ubuntu benign VM's "No bootable medium found" by mounting the
  already-downloaded `ubuntu-26.04-desktop-amd64.iso` to its IDE optical
  drive (it had a blank disk and no ISO attached).
- Fixed a kernel panic in the installer (`vmwgfx` driver crash — "running on
  an unsupported hypervisor") by switching the VM's graphics controller from
  `vmsvga` to `vboxsvga`.
- Fixed host-reported lag in the Ubuntu VM by raising its VRAM 16MB→128MB,
  and right-sized Kali (10,874MB RAM/16 vCPUs → 4096MB/4 vCPUs, since that
  was ~68% of the 16GB host's total memory).
- Completed the Ubuntu install, set static IP `192.168.56.20/24` on `enp0s8`
  ("Wired connection 1") via `nmcli`, matching Kali's `192.168.56.10` setup.
- **M1 done** — host↔Kali and host↔Ubuntu ping clean both directions.
- **M2 done** — but first found and fixed a critical bug: Scapy only
  populates its datalink-dissection table (`conf.l2types`) when
  `scapy.layers.inet`/`l2` is imported, and a capture socket resolves its
  dissection class exactly once, at open time. `core/flow_collector.py` and
  `forensics/packet_logger.py` both imported only the narrow
  `scapy.sendrecv.AsyncSniffer`, so every live-captured packet silently fell
  back to undissected `Raw` — `FlowCollector` would have built zero flows,
  forever, despite pcap capture working fine. Fixed by importing
  `scapy.layers.inet` at module load time in both files; verified against
  real traffic on the lab network.
- **M3 done** — via `lab/target_service.py` + `curl` from the Ubuntu VM. Hit
  a second bug along the way: `_FlowState` closed a flow the instant both
  directions had sent a FIN, but a standard TCP close is
  FIN→ACK→FIN→**ACK** — that trailing ACK arrived to find the flow already
  popped, spawning a phantom one-packet flow per clean connection close.
  Fixed by delaying finalization by one packet. Verified: one curl request
  now produces exactly 1 flow row (`destination_port=80`, `syn=2`, `fin=2`,
  7 fwd / 5 bwd packets) instead of 2.
- 4 commits made this session: the two bugfixes above, on top of last
  session's live-capture-feature and generated-artifacts commits.

**Decisions:**
- `vboxsvga` is the working graphics controller for this Ubuntu Desktop +
  VirtualBox combination — `vmsvga` reliably kernel-panics on boot here.
- Both Scapy bugs were fixed by importing the registration module at load
  time rather than patching each call site, so the fix covers any future
  code in this project that opens a Scapy capture socket.
- FIN-close finalization is delayed by exactly one packet rather than
  building a full TCP state machine — matches the real FIN→ACK→FIN→ACK
  sequence, and the existing idle-timeout sweep already covers the case
  where the trailing packet never arrives.

**Next steps:**
- **M4** — single attack type detection: `sentinel.py live --interface
  "Ethernet 2" --model models\benchmarkids_binary.pkl` on the host, `nmap
  -sS 192.168.56.1` from Kali while Ubuntu keeps generating benign
  curl/ping traffic; confirm Kali's flows classify as `PortScan`/`T1046`
  while Ubuntu's stay benign.
- **M5** — mixed concurrent benign + attack, end-to-end (5-10 min run,
  multiple attack types from Kali: `hping3` flood, `hydra` brute force,
  curl SQLi-shaped payload).
- Install `nmap hydra hping3 slowhttptest curl` on Kali before M4/M5, per
  `lab/README.md`, if not already present.
- Working tree is clean — nothing left uncommitted.

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
