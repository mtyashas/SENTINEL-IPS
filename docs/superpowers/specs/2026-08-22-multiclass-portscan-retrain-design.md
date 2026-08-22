# Multiclass PortScan Retraining from Live Multi-Host Captures — Design Spec

**Date:** 2026-08-22
**Status:** Approved, ready for implementation planning

## Problem

Live multi-host testing on 2026-08-20/21 (see `project_status` memory and
`docs/superpowers/specs/2026-08-18-multihost-lab-topology-design.md`)
measured that 90-97% of network-scan-type detections fall back to the
generic `attack=ATTACK` label with `mitre=T0000/Unknown`, because
`detection/layer1_ml.py`'s multiclass model — trained on CIC-IDS-2017,
captured years ago on a different network — doesn't confidently recognize
live `nmap`/`hping3` traffic's flow-timing shape, even though the binary
model reliably flags it as *an* attack.

Separately, `sentinel.py:241` instantiates a `MistakeCollector()` whose
`.add()` method is never called anywhere in the live pipeline — the
self-learning mechanism that's supposed to close exactly this kind of gap
over time has never actually collected a real mistake, confirmed by
`models/mistakes_buffer.parquet` not existing and every session startup
log reading "loaded 0 existing mistakes."

## Scope

**In scope:** PortScan labeling and retraining only, using last night's two
real PCAP captures. A scan's shape (≤3 packets, no PSH payload) is
genuinely distinctive per-flow, in isolation — no cross-flow signal needed.

**Explicitly out of scope:** DoS/DDoS labeling. A single `hping3` flood
packet is indistinguishable from one failed connection attempt when
looking at that flow alone — telling them apart needs a cross-flow
connection-rate feature (e.g. extending `core/flow_collector.py`'s
existing `beacon_score()` — built for slow periodic C2 check-ins — with
thresholds tuned for fast bursts instead) that doesn't exist yet, and
which could in any case only ever be computed for live-captured traffic,
never retroactively for CIC-IDS-2017/2018 (only their pre-extracted CSVs
are available, not raw PCAPs). Tracked as a separate follow-up project,
not attempted here.

**Explicitly not touched:** the six Layer-2 signature-detected categories
(SQLi, XSS, CommandInject, PathTraversal, WebShell, CSRF) — those are
already correctly named 100% of the time by deterministic payload
matching, independent of the multiclass model. Fixing PortScan doesn't
change how they're detected.

**`MistakeCollector` wiring into the live pipeline** — also explicitly out
of scope for this effort. This spec uses `MistakeCollector` as a
standalone offline tool (matching how the existing precedent script uses
it), not fixing its live-pipeline disconnection. That's a separate,
already-identified follow-up.

## Existing precedent — adapt, don't rebuild

`lab/m5_multiclass_retrain.py` already implements this exact pattern
end-to-end, for an earlier (2026-07-29) single-attacker-VM capture:
reprocess a PCAP through `FlowCollector`, label flows by `src_ip` +
flow-shape, run the current production multiclass model to find where it
disagrees with ground truth, feed those mistakes into `AdaptiveTrainer`
(already generalized for multiclass via its `mode` parameter) combined
with a CIC-IDS-2017 sample, retrain, and keep the new model only if it's
measurably better on a held-out test set.

Its `label_flows()` heuristic — `total_fwd_packets + total_backward_packets
<= 3` and `psh_flag_count == 0` → `PortScan`; any attacker-sourced flow
otherwise → `WebAttack` (CIC-IDS-2017 itself collapses SQLi/XSS/Command
Injection into one `WebAttack` class, so this is the correct available
label for that traffic, and it's moot anyway since Layer 2 signatures
already handle it) — is dataset-agnostic and gets reused unchanged.

## What's different for last night's data

**New script:** `lab/m6_multiclass_retrain_multihost.py`, following the
existing `m4`/`m5` lab numbering convention. Not a modification of `m5` —
`m5` stays as-is, a reference for its own capture.

**Multiple attacker/benign IP pairs, not one hardcoded pair.** Confirmed
by direct packet inspection of both captures:

| Run | PCAP | Attacker IP(s) | Benign IP(s) |
|---|---|---|---|
| 1 (single laptop) | `pcap/sentinel_20260820_124005_6571ee5e.pcap` | `192.168.0.100` | `192.168.0.104` |
| 2 (3-way multi-host) | `pcap/sentinel_20260820_192521_bc0ea8f1.pcap` | `192.168.0.150` (niki), `192.168.0.151` (brindha) | `192.168.0.104` (niki, low volume — ~106 packets, consistent with the mid-run benign-script bug that was fixed partway through), `192.168.0.108` (brindha — ~452 packets) |

`label_flows()` takes lists of attacker/benign IPs instead of single
constants, and is called once per PCAP, with results concatenated before
the retrain step.

**Collision-window exclusion.** Early in Run 2, both Kalis briefly shared
DHCP-assigned `192.168.0.100` before the static-IP fix (`.150`/`.151`).
Any flow sourced from `192.168.0.100` in Run 2 is excluded from labeling —
ambiguous which physical laptop sent it. (In practice, direct packet
inspection shows `.100` barely appears in Run 2's capture at all — the
collision window was short — but the exclusion is kept for correctness
regardless of how small its practical effect turns out to be.)

**Two PCAPs combined, not one.** `m5` only ever processed a single
capture. This script reprocesses both, concatenating the labeled flow
sets before building the training cache — more real PortScan examples
from two independent live-capture sessions rather than one.

## Validation

Identical to `m5`'s own approach, kept unchanged: `AdaptiveTrainer.retrain()`
is given a stratified held-out slice of the CIC-IDS-2017 sample as its test
set. The new model replaces the production model only if macro recall/F1
measurably improves on that held-out set — report `PASS`/`NO IMPROVEMENT`
explicitly, matching `m5`'s existing log output, not just "retraining
happened." Before/after accuracy on the live captures themselves (not just
the CIC-2017 held-out set) is also printed, exactly as `m5` does.

## Testing

The script's own before/after accuracy comparison on the live captures
*is* the test — this mirrors how `m5` and the rest of this project's lab
scripts self-validate (no separate pytest suite; `python lab/m6_...py`
run directly is the verification, matching the project's established
`lab/verify_*.py` / `lab/m*.py` convention). Success criteria: `PASS`
verdict from `AdaptiveTrainer`, and a measurable drop in the fraction of
attacker-sourced scan-shaped flows still falling back to `ATTACK`/`T0000`
when re-evaluated with the new model.

## File structure changes

```
lab/
└── m6_multiclass_retrain_multihost.py   NEW — adapted from m5, multi-IP,
                                          multi-PCAP, collision-excluded

models/
├── train_cache_multiclass_multihost.parquet   NEW (script output, cache)
└── mistakes_buffer_multiclass_multihost.parquet NEW (script output, cache)
```

No changes to `sentinel.py`, `detection/layer1_ml.py`,
`adaptive/adaptive_trainer.py`, or `adaptive/mistake_collector.py` — all
reused exactly as they exist today.
