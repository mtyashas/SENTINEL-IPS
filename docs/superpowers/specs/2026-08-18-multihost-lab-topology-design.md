# Multi-Host Lab Topology — Design Spec

**Date:** 2026-08-18
**Status:** Approved, no source-code implementation required

## Problem

The documented lab topology (`lab/README.md`) assumes one physical machine: the
Windows host and both VMs (Kali attacker, Ubuntu-benign) share a single
VirtualBox Host-Only Network (`192.168.56.0/24`), which only exists within
that one host — it cannot span physical machines. Starting tomorrow, Kali and
Ubuntu move onto two separate physical laptops, so this topology no longer
works: the Windows laptop can't see VirtualBox-internal traffic happening on
someone else's machine.

## Why this matters beyond tomorrow

The end goal (per `CLAUDE.md`) is server-level protection where many
independent devices connect to a protected server. A flat peer network where
attacker/benign/server all share one virtual switch (the old host-only model)
doesn't reflect that — a real server is a distinct role that client devices
*connect to*, not a peer among equals. Tomorrow's 3-laptop test is worth
treating as a rehearsal of the real target architecture, not just a lab
workaround: Windows laptop = server, Kali/Ubuntu laptops = independent
clients, exactly like real devices hitting a real server.

## Topology

- **Windows laptop** — stays the "protected server": runs `sentinel.py live`,
  `lab/target_service.py`, and the honeypot listeners, all bound to its real
  WiFi NIC.
- **Kali laptop, Ubuntu laptop** — independent clients on the same WiFi.
  VMs stay on VirtualBox's **default NAT** adapter (not Bridged, not
  Host-Only) — their traffic exits through each laptop's own normal WiFi
  connection to reach the Windows laptop, indistinguishable from that
  laptop's own traffic.

**Why NAT over Bridged:** VirtualBox Bridged Adapter mode over WiFi is a
known-unreliable pattern — many routers (especially venue/public ones) apply
client isolation or reject a VM's separate MAC address on the same radio,
and it can fail unpredictably with no in-session fix. NAT mode sidesteps this
entirely since the VM's traffic is carried by the laptop's already-associated
WiFi connection. The tradeoff — logged `src_ip` becomes the laptop's WiFi IP
rather than a synthetic per-VM IP — doesn't matter here: attacker vs. benign
is still cleanly distinguished, since they're two different physical
machines.

**Decision procedure for tomorrow:** don't assume either mode blind. Run a
2-minute Bridged-mode probe (`ping` from the VM to the Windows laptop) per
laptop first; fall back to NAT immediately on failure rather than debugging
WiFi/AP behavior live. The two laptops' outcomes are independent — one could
end up Bridged, the other NAT.

## IP addressing

No more fixed `.10`/`.20`/`.1` scheme — the venue WiFi's DHCP assigns real
addresses. Read actual IPs off each laptop (`ipconfig` / `ip addr`) once
connected, at the start of the session, rather than hardcoding anything.

## Windows Firewall

Last session's live-test findings (see `docs/SESSION_LEDGER.md`,
2026-08-02) flagged that Windows Firewall's Public profile blocks inbound
traffic, and considering flipping the whole Public profile on was noted as
risky since it'd affect all WiFi traffic broadly, not just this lab. For
tomorrow: use scoped inbound-allow rules instead —
`netsh advfirewall firewall add rule` for exactly the ports SENTINEL needs
(80 for `target_service.py`; 2222/2121/8080/5432/9000 for the honeypot
services per `config.py`'s `HONEYPOT_SERVICES`) — these apply regardless of
network profile, without changing the Public profile's default posture at
all. More surgical than the options considered previously.

## What needs to change in the repo

**No source code changes.** Verified against current defaults:
- `LIVE_BPF_FILTER = "tcp or udp"` (`config.py`) — already has no subnet
  restriction.
- `--interface` / `--host` — already CLI-overridable
  (`sentinel.py live --interface <adapter>`, `target_service.py --host`).
- Honeypot listeners already bind `0.0.0.0` (`intelligence/honeypot.py`).

This is new network configuration plus a runbook, not a code change. The
runbook itself is documented as a new section in `lab/README.md`, alongside
the existing single-host topology — that's where this project already
records lab setup decisions.

## Runbook (also mirrored in `lab/README.md`)

1. All 3 laptops join the same WiFi. Note each laptop's actual IP.
2. Bridged-mode probe per new laptop (ping test); fall back to NAT on
   failure.
3. Add scoped Windows Firewall inbound rules for ports 80, 2222, 2121, 8080,
   5432, 9000.
4. `python lab\target_service.py --host 0.0.0.0`
5. Resolve the Windows laptop's real WiFi adapter name (same
   `get_windows_if_list()` approach as the existing Npcap resolution step,
   picking the WiFi adapter instead of the VirtualBox one), then
   `python sentinel.py live --interface <resolved WiFi adapter name>`
6. Point Kali's attack tools and `lab/gen_benign_traffic.sh` at the Windows
   laptop's actual WiFi IP from step 1.
