# DoS/DDoS Multiclass Retraining via a New Cross-Flow Rate Feature — Design Spec

**Date:** 2026-08-23
**Status:** Approved, ready for implementation planning

## Problem

`docs/superpowers/specs/2026-08-22-multiclass-portscan-retrain-design.md`
fixed PortScan's generic-`ATTACK`-fallback problem but explicitly excluded
DoS/DDoS: a single `hping3` flood packet is indistinguishable from one
failed connection attempt when looking at that flow's own features in
isolation — no cross-flow rate signal exists in the current schema. This
spec builds that signal and closes the gap for DoS specifically.

## Why `beacon_score()` isn't the answer

`core/flow_collector.py`'s `beacon_score()` already tracks connection
regularity per `(src_ip, dst_ip)` pair for Bot/C2 detection, but its own
constants document exactly why it can't be reused as-is:
`_BEACON_MIN_MEAN_INTERVAL_S = 2.0` exists specifically because a fast,
evenly-paced port scan has the same low coefficient-of-variation as a
genuine slow beacon — confirmed live 2026-08-01, `nmap -sS` got
mislabelled `Bot`. Anything faster than 2 seconds is deliberately excluded
from beacon scoring. That excluded fast range is exactly where both scans
and floods live — but a scan and a flood need different signals from each
other too (port diversity vs. raw rate), so this needs a genuinely new
method, not a threshold tweak to the existing one.

## Architecture

**New method, not new tracking infrastructure.** `FlowCollector` already
maintains `self._conn_history: Dict[(src_ip, dst_ip), deque]` —
connection start timestamps per pair, populated unconditionally for every
new flow (`core/flow_collector.py` around line 621), not just for
beaconing. Add `connection_rate(src_ip, dst_ip) -> float` as a sibling to
`beacon_score()`, reading the same deque, computing raw
connections-per-second instead of regularity:

```python
def connection_rate(self, src_ip: str, dst_ip: str) -> float:
    history = self._conn_history.get((src_ip, dst_ip))
    if history is None or len(history) < 2:
        return 0.0
    span = history[-1] - history[0]
    if span <= 0:
        return float(len(history))
    return (len(history) - 1) / span
```

No changes to `ingest_packet()` or any other write path — this is a pure
read-side addition.

**Live-pipeline wiring.** `sentinel.py`'s `_run_live()` already has a
precedent for exactly this pattern: `_add_beacon_column()` queries
`collector.beacon_score(s, d)["is_beacon"]` per unique `(src_ip, dst_ip)`
pair in a chunk and adds it as a column, after `FlowCollector` produces
the flow DataFrame, before `process_chunk()`. Add a sibling
`_add_connection_rate_column()` following the identical structure, adding
a `conn_rate_per_sec` column.

**Retraining script.** New `lab/m7_multiclass_retrain_dos.py` (matching
the `m5`/`m6` numbering; neither existing script is modified). Reprocesses
the same two PCAPs from `docs/superpowers/specs/2026-08-22-multiclass-portscan-retrain-design.md`
(`pcap/sentinel_20260820_124005_6571ee5e.pcap`,
`pcap/sentinel_20260820_192521_bc0ea8f1.pcap`), computing
`connection_rate()` for each labeled flow's `(src_ip, dst_ip)` pair using
the same IP tables and collision-window exclusion `m6` established.
Extends the labeling heuristic: attacker-sourced flow with a connection
rate above a tuned threshold → `DoS` (single-source flood — our captures
never had two attackers flooding the same target concurrently, so `DoS`
is the honest label, not `DDoS`; the `DDoS` class in `ATTACK_CLASSES`
stays unaddressed by this effort). Everything below the threshold keeps
falling through to `m6`'s existing PortScan/WebAttack/BENIGN logic
unchanged. Retrains via the same `AdaptiveTrainer` pattern established in
`m6`: cache combined with a CIC-IDS-2017 sample, held-out validation,
keep the new model only if it measurably improves.

## Known limitation (explicit, not hidden)

The new `conn_rate_per_sec` feature can only ever be genuinely populated
for our own live-captured PCAPs — CIC-IDS-2017/2018 rows get a
default/zero value, since only their pre-extracted CSVs exist, not raw
packets. This is a real dataset-shortcut risk: the model could learn
"this feature is nonzero" as a proxy for "this is our live-capture data"
rather than learning genuine flood behavior. This is accepted and
disclosed rather than mitigated with synthetic historical values (which
would just trade one kind of artificiality for another) — matching the
same honest-tradeoff approach the PortScan fix took with its F1 dip. The
held-out CIC-2017 validation set structurally cannot fully validate this
feature either way, since it can never contain a real value for it; the
actual validation is future live tests exhibiting correctly-labeled DoS
detections, not this round's held-out metric alone.

## Known limitations (additional)

**Narrow sample, same as the PortScan fix.** This is tuned against exactly
one `hping3 --flood` invocation on one WiFi hotspot's baseline traffic
conditions. It closes the specific gap measured on these two captures —
not a general robustness guarantee across flood tools, rates, or network
environments. Worse than PortScan's version of this caveat: a raw
connections-per-second threshold tuned on a quiet lab network risks
false-positiving in a genuinely busy production environment (e.g. many
real users behind one NAT gateway legitimately opening connections fast).
Add `# ponytail`-style known-ceiling documentation on `connection_rate()`
itself, matching `beacon_score()`'s own existing pattern, rather than
presenting the threshold as validated for production traffic volumes.

**Naive threshold is evadable by design, not just by accident.** A rate
threshold can always be defeated by an attacker who deliberately throttles
below it — a "low-and-slow" flood. `beacon_score()`'s own docstring
already states this same honest limit for its own heuristic ("catches
unsophisticated/naive beaconing, not evasive C2 -- upgrade path is a
proper time-series/frequency-domain analysis if that's ever needed").
`connection_rate()` gets the identical class of limitation and should
document it the same way, not imply robustness the mechanism doesn't have.

## Validation

Same as `m6`: `AdaptiveTrainer.retrain()` against a stratified held-out
CIC-IDS-2017 slice, PASS/NO IMPROVEMENT verdict based on measured
recall/F1 change. Additionally, before/after accuracy specifically on the
DoS-labeled portion of the combined live captures (mirroring `m6`'s
combined-capture accuracy check), since that's the metric that actually
reflects whether this fix works, given the held-out set's structural
blind spot noted above.

## Testing

Matches this project's established `lab/` convention (no pytest suite):
`FlowCollector.connection_rate()` is a pure function over existing state
and gets a direct unit test, same treatment as `m6`'s `label_flows()`
test. The full retrain script's own printed before/after accuracy and
PASS/NO IMPROVEMENT verdict is the integration-level verification, run
directly rather than through a test framework.

## File structure changes

```
core/
└── flow_collector.py           MODIFIED — add connection_rate() method only

sentinel.py                     MODIFIED — add _add_connection_rate_column(),
                                 call it in _run_live() alongside the existing
                                 _add_beacon_column()

lab/
├── m7_multiclass_retrain_dos.py       NEW — everything for this effort
└── test_flow_collector_connection_rate.py   NEW — unit test for connection_rate()

models/
├── train_cache_multiclass_dos.parquet     NEW (script output, cache)
└── mistakes_buffer_multiclass_dos.parquet NEW (script output, cache — deleted on
                                                 successful retrain, matching
                                                 MistakeCollector.clear()'s existing behavior)
```

`m5_multiclass_retrain.py` and `m6_multiclass_retrain_multihost.py` are
not modified.
