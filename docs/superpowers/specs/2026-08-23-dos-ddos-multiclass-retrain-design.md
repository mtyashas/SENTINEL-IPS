# DoS/DDoS Detection via a Rule-Based Cross-Flow Rate Signal — Design Spec

**Date:** 2026-08-23 (revised same day — see Revision History)
**Status:** Approved, ready for implementation planning

## Problem

`docs/superpowers/specs/2026-08-22-multiclass-portscan-retrain-design.md`
fixed PortScan's generic-`ATTACK`-fallback problem but explicitly excluded
DoS/DDoS: a single `hping3` flood packet is indistinguishable from one
failed connection attempt when looking at that flow's own features in
isolation — no cross-flow rate signal exists in the current schema. This
spec closes that gap.

## Revision History

**Original approach (superseded):** the first version of this spec
proposed a new `conn_rate_per_sec` feature fed into a multiclass model
retrain, mirroring `docs/superpowers/specs/2026-08-22-multiclass-portscan-retrain-design.md`'s
pattern exactly. That approach is **not used** — see below.

**Why it changed:** `lab/verify_beacon_detection.py`'s docstring revealed
that this exact class of problem (a cross-flow signal the per-flow ML
model has no visibility into) was already solved once before, for
Bot/C2 beacon detection, and *not* via retraining: "adding a genuinely
new stateful feature to the trained ML models would need recomputing it
across the entire CIC-2017 training set, a much bigger lift than this
architectural gap needs to justify." Instead, `FlowCollector.beacon_score()`
feeds a **rule-based override** — `sentinel.py`'s `_run_beacon()` —
that directly promotes a beacon-flagged flow to `Bot`/`pred_binary=1`,
bypassing the multiclass model entirely. This is a proven, already-shipped
pattern in this exact codebase, for the same shape of problem, and it
eliminates the dataset-shortcut risk the original approach explicitly
disclosed (there is no retraining, so there is no CIC-2017/2018
compatibility question at all). Given this project's use case is
server-level security (not a one-off lab demo), the simpler, already-
validated mechanism is the better call.

## Architecture

**New method on `FlowCollector`, mirroring `beacon_score()`'s exact
shape.** `core/flow_collector.py` already maintains
`self._conn_history: Dict[(src_ip, dst_ip), deque]` — connection start
timestamps per pair, populated unconditionally for every new flow (around
line 621), the same history `beacon_score()` reads. Add
`connection_rate(src_ip, dst_ip) -> dict`, returning a decided boolean
(`is_flood`) plus supporting detail, the same shape `beacon_score()`
returns (`conn_count`, `is_beacon`, ...):

```python
_DOS_MIN_CONNECTIONS    = 2      # minimum history before scoring at all
_DOS_RATE_THRESHOLD_PER_S = 10.0 # connections/sec at or above this = flood-shaped

def connection_rate(self, src_ip: str, dst_ip: str) -> dict:
    """
    Cross-flow connection-rate signal for one (src_ip, dst_ip) pair, for
    DoS/DDoS flood detection. Reads the same _conn_history beacon_score()
    uses, just interpreted as raw rate instead of regularity --
    beacon_score() deliberately excludes anything faster than
    _BEACON_MIN_MEAN_INTERVAL_S (2s) since a fast, evenly-paced scan looks
    identical to a beacon by regularity alone; this is the signal for
    that excluded fast range.

    Naive threshold, same class of limitation as beacon_score()'s own CV
    heuristic: catches a flood at a fixed rate, tuned against this lab's
    own hping3 capture -- not validated against production-scale
    legitimate traffic (e.g. many real users behind one NAT gateway could
    plausibly open connections fast enough to cross a poorly-chosen
    threshold), and defeated by an attacker who deliberately throttles
    below it. See "Known limitations" below.

    Inputs:  src_ip, dst_ip -- the pair to score
    Outputs: dict with conn_count, is_flood (bool), rate_per_sec (float,
             None if fewer than _DOS_MIN_CONNECTIONS connections recorded)
    """
    with self._lock:
        history = list(self._conn_history.get((src_ip, dst_ip), ()))

    if len(history) < _DOS_MIN_CONNECTIONS:
        return {"conn_count": len(history), "is_flood": False, "rate_per_sec": None}

    span = history[-1] - history[0]
    rate = float(len(history)) if span <= 0 else (len(history) - 1) / span
    is_flood = rate >= _DOS_RATE_THRESHOLD_PER_S
    return {"conn_count": len(history), "is_flood": is_flood, "rate_per_sec": round(rate, 2)}
```

**Live-pipeline wiring, mirroring `_add_beacon_column()`/`_run_beacon()`
exactly.** `sentinel.py`'s `_run_live()` already populates a
`beacon_detected` column via `_add_beacon_column()` (queries
`collector.beacon_score(s, d)["is_beacon"]` per unique `(src_ip, dst_ip)`
pair in the chunk, before `process_chunk()`). Add a sibling
`_add_dos_column()` populating a `dos_flagged` column from
`collector.connection_rate(s, d)["is_flood"]`, called at the identical
two call sites `_add_beacon_column()` already has (main loop and
`KeyboardInterrupt` flush).

Add `SentinelIPS._run_dos()`, mirroring `_run_beacon()`'s exact structure
(precedence: never override an existing signature match; promote to
`sig_attack_type="DoS"`, `pred_binary=1`, `confidence` floor 0.75, same
as beacon's 0.75 floor and same reasoning — a rate inference, not an exact
pattern hit). Called at the same pipeline position `_run_beacon()` is
(`sentinel.py:304`), immediately after it, so both cross-flow rule stages
run before Layer 3 anomaly detection sees the chunk.

Single-source only: our captures never had two attackers flooding the
same target concurrently, so this labels `DoS`, not `DDoS` — the `DDoS`
class in `ATTACK_CLASSES` stays unaddressed by this effort.

## Known limitations (unchanged from the superseded version, still apply)

**Narrow sample.** Tuned against exactly one `hping3 --flood` invocation
on one WiFi hotspot's baseline traffic conditions — closes the specific
gap measured on these two captures, not a general robustness guarantee.

**Threshold risk at production scale.** A raw connections-per-second
threshold tuned on a quiet lab network risks false-positiving in a
genuinely busy production environment (many real users behind one NAT
gateway legitimately opening connections fast). Given this project's
stated goal is real server-level protection, not just a lab demo, this is
a real gap for production readiness, not a cosmetic caveat — tracked
explicitly as a follow-up: a genuinely production-grade version would use
an *adaptive, baseline-relative* threshold (e.g. "N times this specific
server's own typical rate," learned per-deployment) rather than one
hardcoded global number. Not attempted in this round.

**Evadable by design.** A rate threshold is always defeated by an
attacker who deliberately throttles below it (a "low-and-slow" flood) --
the identical class of limitation `beacon_score()`'s own docstring
already discloses for itself ("catches unsophisticated/naive beaconing,
not evasive C2").

## What's eliminated by this revision

The dataset-shortcut risk from the superseded retrain-based approach no
longer applies -- there is no retraining, so there is no question of a
new feature column being populated only for live data and never for
CIC-2017/2018.

## Testing

Matches `lab/verify_beacon_detection.py`'s exact pattern (same file this
whole design is modeled on): synthetic Scapy packets fed through
`FlowCollector.ingest_packet()` via a `make_connection()` helper, at
controlled timestamps, to exercise `connection_rate()` directly --
regular-but-slow (not a flood), regular-and-fast (a flood), and a
below-history-minimum case. Then a second check exercising `_run_dos()`
directly on a synthetic chunk, mirroring `verify_beacon_detection.py`'s
Check 4/5 (promotion behavior, precedence against an existing signature
match, and the simulate-mode no-op case where `dos_flagged` is absent).

## File structure changes

```
core/
└── flow_collector.py           MODIFIED — add connection_rate() + its
                                 _DOS_* constants, adjacent to beacon_score()

sentinel.py                     MODIFIED — add _add_dos_column() (mirrors
                                 _add_beacon_column()) and _run_dos()
                                 (mirrors _run_beacon()); wire both at the
                                 same call sites as their beacon siblings

lab/
└── verify_dos_detection.py     NEW — mirrors verify_beacon_detection.py's
                                 structure exactly, for connection_rate()
                                 and _run_dos()
```

No changes to `lab/m5_multiclass_retrain.py`,
`lab/m6_multiclass_retrain_multihost.py`, `detection/layer1_ml.py`,
`adaptive/adaptive_trainer.py`, or `adaptive/mistake_collector.py` — this
approach touches none of them. No new `lab/m7_*.py` retraining script,
no new `models/*.parquet` cache files — this revision needs neither.
