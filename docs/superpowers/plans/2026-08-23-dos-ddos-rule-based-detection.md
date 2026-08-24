# DoS/DDoS Rule-Based Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a rule-based `DoS` detection override — mirroring the existing Bot/beacon detection pattern exactly — so flood-shaped traffic (like `hping3 --flood`) gets correctly labeled instead of falling back to the generic `ATTACK` class.

**Architecture:** `FlowCollector.connection_rate()` (new, mirrors `beacon_score()`'s shape) reads the same existing `_conn_history` cross-flow state to compute a connections-per-second rate per `(src_ip, dst_ip)` pair. `sentinel.py`'s `_add_dos_column()` (mirrors `_add_beacon_column()`) populates a `dos_flagged` column on live flow chunks; `_run_dos()` (mirrors `_run_beacon()`) promotes any flagged flow straight to `DoS`/`pred_binary=1`, bypassing the multiclass model entirely — no retraining involved.

**Tech Stack:** Python, existing `core.flow_collector.FlowCollector`, `sentinel.SentinelIPS`, scapy (`IP`/`TCP`) for the test harness.

**Spec:** `docs/superpowers/specs/2026-08-23-dos-ddos-multiclass-retrain-design.md` (title predates the mid-design revision to a rule-based approach — see that file's own "Revision History" section for why)

## Global Constraints

- No changes to `lab/m5_multiclass_retrain.py`, `lab/m6_multiclass_retrain_multihost.py`, `detection/layer1_ml.py`, `adaptive/adaptive_trainer.py`, or `adaptive/mistake_collector.py`. This approach touches none of them — no retraining, no new model files, no new `lab/m7_*.py` script.
- `_DOS_MIN_CONNECTIONS = 2`, `_DOS_RATE_THRESHOLD_PER_S = 10.0` — exact values from the spec.
- `connection_rate()` must acquire `self._lock` before reading `self._conn_history`, matching `beacon_score()`'s existing thread-safety pattern exactly (`core/flow_collector.py:703`).
- `_run_dos()` confidence floor is 0.75, identical to `_run_beacon()`'s — same reasoning (a rate inference, not an exact signature match), not a new number to justify separately.
- Known limitations (state these in code comments, not just the spec): naive fixed threshold, tuned on one lab capture, not validated at production traffic scale; evadable by an attacker who throttles below it. Mirror `beacon_score()`'s own documented-limitation style, don't imply more robustness than the mechanism has.

---

## File Structure

```
core/
└── flow_collector.py           MODIFIED — add connection_rate() + _DOS_*
                                 constants, placed directly after beacon_score()

sentinel.py                     MODIFIED — add _add_dos_column() next to
                                 _add_beacon_column(), _run_dos() next to
                                 _run_beacon(); wire both at the same call
                                 sites as their beacon siblings

lab/
└── verify_dos_detection.py     NEW — mirrors lab/verify_beacon_detection.py's
                                 structure exactly
```

---

### Task 1: `FlowCollector.connection_rate()`

**Files:**
- Modify: `core/flow_collector.py` (add constants + method after `beacon_score()`, which ends at line 725)
- Create: `lab/verify_dos_detection.py` (Checks 1-3 only at this stage)

**Interfaces:**
- Produces: `FlowCollector.connection_rate(src_ip: str, dst_ip: str) -> dict` — keys `conn_count` (int), `is_flood` (bool), `rate_per_sec` (float, or `None` if `conn_count < _DOS_MIN_CONNECTIONS`).

- [ ] **Step 1: Write the failing test**

```python
"""
lab/verify_dos_detection.py

Purpose: Self-check for rule-based DoS/DDoS detection (2026-08-23,
         mirroring lab/verify_beacon_detection.py's exact structure).
         core.flow_collector.FlowCollector.connection_rate() reads the
         same cross-flow _conn_history beacon_score() uses, interpreted
         as raw rate instead of regularity -- confirmed live 2026-08-20/21:
         an hping3 SYN flood was reliably caught by the binary model but
         the multiclass model couldn't name it, falling back to the
         generic ATTACK label with no MITRE mapping (severity capped at
         MEDIUM, since attack-type-keyed lookups have nothing to match).
         Fixed with a rule-based override
         (sentinel.py._run_dos()/_add_dos_column()), the same pattern
         already used for Bot/beacon detection, rather than a multiclass
         retrain -- see
         docs/superpowers/specs/2026-08-23-dos-ddos-multiclass-retrain-design.md's
         Revision History for why.

         Confirms: (1) fast, regular connections (flood-shaped) score as
         a flood, (2) slow/occasional connections (ordinary traffic)
         don't, (3) too little history (below _DOS_MIN_CONNECTIONS)
         returns rate_per_sec=None rather than a misleading 0.0.

Usage:
    python lab/verify_dos_detection.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scapy.layers.inet import IP, TCP

from core.flow_collector import FlowCollector

SRC, DST = "192.168.56.10", "192.168.56.1"


def make_connection(collector: FlowCollector, sport: int, ts: float) -> None:
    """One minimal 2-packet 'connection' (SYN + RST) at a given src port
    and timestamp -- enough for FlowCollector to register a new flow."""
    syn = IP(src=SRC, dst=DST) / TCP(sport=sport, dport=80, flags="S", seq=1000)
    syn.time = ts
    collector.ingest_packet(syn)
    rst = IP(src=DST, dst=SRC) / TCP(sport=80, dport=sport, flags="R", seq=5000, ack=1001)
    rst.time = ts + 0.001
    collector.ingest_packet(rst)


print("--- Check 1: fast, regular connections (flood-shaped) score as a flood ---")
collector = FlowCollector()
base = 1_000_000.0
for i in range(10):
    make_connection(collector, sport=40000 + i, ts=base + i * 0.01)   # 100 conns/sec
score = collector.connection_rate(SRC, DST)
print(f"Flood-shaped: {score}")
assert score["is_flood"], f"FAIL: fast repeated connections not flagged as a flood: {score}"
assert score["rate_per_sec"] > 50.0, f"FAIL: expected rate well above threshold: {score}"
print("PASS: fast, regular connections correctly flagged as a flood")

print()
print("--- Check 2: slow/occasional connections (ordinary traffic) do NOT score as a flood ---")
collector2 = FlowCollector()
offsets = [0, 12, 30, 65, 140]   # a handful of requests over ~2.5 minutes
for i, off in enumerate(offsets):
    make_connection(collector2, sport=50000 + i, ts=base + off)
score2 = collector2.connection_rate(SRC, DST)
print(f"Ordinary: {score2}")
assert not score2["is_flood"], f"FAIL: ordinary-paced connections incorrectly flagged as a flood: {score2}"
print("PASS: ordinary-paced connections correctly NOT flagged")

print()
print("--- Check 3: too little history returns rate_per_sec=None, not a misleading 0.0 ---")
collector3 = FlowCollector()
make_connection(collector3, sport=60000, ts=base)   # only 1 connection
score3 = collector3.connection_rate(SRC, DST)
print(f"Insufficient history: {score3}")
assert score3["conn_count"] == 1
assert not score3["is_flood"]
assert score3["rate_per_sec"] is None, f"FAIL: expected None with insufficient history: {score3}"
print("PASS: insufficient history correctly returns rate_per_sec=None")

print()
print("All checks passed.")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python lab/verify_dos_detection.py`
Expected: `AttributeError: 'FlowCollector' object has no attribute 'connection_rate'`

- [ ] **Step 3: Add the constants and method to `core/flow_collector.py`**

Insert directly after `beacon_score()` (which ends at line 725):

```python

    _DOS_MIN_CONNECTIONS      = 2      # minimum history before scoring at all
    _DOS_RATE_THRESHOLD_PER_S = 10.0   # connections/sec at or above this = flood-shaped

    def connection_rate(self, src_ip: str, dst_ip: str) -> dict:
        """
        Cross-flow connection-rate signal for one (src_ip, dst_ip) pair,
        for DoS/DDoS flood detection. Reads the same _conn_history
        beacon_score() uses, just interpreted as raw rate instead of
        regularity -- beacon_score() deliberately excludes anything
        faster than _BEACON_MIN_MEAN_INTERVAL_S (2s) since a fast,
        evenly-paced scan looks identical to a beacon by regularity
        alone; this is the signal for that excluded fast range.

        Naive threshold, same class of limitation as beacon_score()'s own
        CV heuristic: catches a flood at a fixed rate, tuned against this
        lab's own hping3 capture -- not validated against production-
        scale legitimate traffic (e.g. many real users behind one NAT
        gateway could plausibly open connections fast enough to cross a
        poorly-chosen threshold), and defeated by an attacker who
        deliberately throttles below it. See
        docs/superpowers/specs/2026-08-23-dos-ddos-multiclass-retrain-design.md
        for the full disclosed limitation.

        Inputs:  src_ip, dst_ip -- the pair to score
        Outputs: dict with conn_count, is_flood (bool), rate_per_sec
                 (float, None if fewer than _DOS_MIN_CONNECTIONS
                 connections recorded)
        """
        with self._lock:
            history = list(self._conn_history.get((src_ip, dst_ip), ()))

        if len(history) < self._DOS_MIN_CONNECTIONS:
            return {"conn_count": len(history), "is_flood": False, "rate_per_sec": None}

        span = history[-1] - history[0]
        rate = float(len(history)) if span <= 0 else (len(history) - 1) / span
        is_flood = rate >= self._DOS_RATE_THRESHOLD_PER_S
        return {"conn_count": len(history), "is_flood": is_flood, "rate_per_sec": round(rate, 2)}
```

Note: `_DOS_MIN_CONNECTIONS`/`_DOS_RATE_THRESHOLD_PER_S` are defined as
class attributes here (`self._DOS_MIN_CONNECTIONS`), not module-level
constants like `_BEACON_*` — this is a deliberate deviation from
`beacon_score()`'s exact style, made because `beacon_score()`'s
module-level constants are referenced only within that one method, while
keeping these as class attributes makes them overridable per-instance in
the Task 2 test without needing to patch module globals. If a reviewer
prefers strict consistency with the `_BEACON_*` module-level style
instead, that's an equally valid choice — either way, the values
(`2` and `10.0`) and the method's behavior must stay identical.

- [ ] **Step 4: Run test to verify it passes**

Run: `python lab/verify_dos_detection.py`
Expected: three `PASS` lines, then `All checks passed.`

- [ ] **Step 5: Commit**

```bash
git add core/flow_collector.py lab/verify_dos_detection.py
git commit -m "feat: add FlowCollector.connection_rate() for DoS/DDoS detection"
```

---

### Task 2: `sentinel.py` rule-based DoS override

**Files:**
- Modify: `sentinel.py` (add `_add_dos_column()` near `_add_beacon_column()` at line 1109; add `_run_dos()` near `_run_beacon()` at line 510; wire both)
- Modify: `lab/verify_dos_detection.py` (extend with Checks 4-5)

**Interfaces:**
- Consumes: `FlowCollector.connection_rate(src_ip, dst_ip) -> dict` (Task 1), keyed by `"is_flood"`.
- Produces: `SentinelIPS._run_dos(self, chunk: pd.DataFrame) -> pd.DataFrame` — reads a `dos_flagged` column if present, no-op otherwise (matching `_run_beacon()`'s `beacon_detected` handling exactly).

- [ ] **Step 1: Extend the test with the failing `_run_dos()` checks**

Append to `lab/verify_dos_detection.py`, before the final `print("All checks passed.")` block (move that block to the very end after these new checks):

```python
import pandas as pd

from sentinel import SentinelIPS

print()
print("--- Check 4: _run_dos() promotes a flood-flagged flow to DoS ---")
ips = SentinelIPS()  # no model_path needed -- _run_dos never touches layer1
chunk = pd.DataFrame({
    "dos_flagged":     [True, False],
    "src_ip":          [SRC, SRC],
    "destination_port": [80, 80],
})
result = ips._run_dos(chunk)
assert result.iloc[0]["sig_attack_type"] == "DoS"
assert result.iloc[0]["pred_binary"] == 1
assert result.iloc[0]["confidence"] >= 0.75
assert pd.isna(result.iloc[1]["sig_attack_type"]), "non-flagged row should be untouched"
print(f"PASS: flood-flagged row -> sig_attack_type=DoS, confidence={result.iloc[0]['confidence']:.2f}; "
      f"non-flagged row untouched")

print()
print("--- Check 5: chunk with no dos_flagged column (simulate mode) is a no-op ---")
plain_chunk = pd.DataFrame({"src_ip": [SRC]})
result = ips._run_dos(plain_chunk)
assert "sig_attack_type" not in result.columns
assert result.equals(plain_chunk)
print("PASS: simulate-mode chunk (no dos_flagged column) passed through untouched")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python lab/verify_dos_detection.py`
Expected: `AttributeError: 'SentinelIPS' object has no attribute '_run_dos'`

- [ ] **Step 3: Add `_run_dos()` to `sentinel.py`**

Insert directly after `_run_beacon()` (which ends at line 556):

```python

    def _run_dos(self, chunk: pd.DataFrame) -> pd.DataFrame:
        """
        Rule-based cross-flow DoS/DDoS detection. Layer 1's per-flow ML
        features have no visibility into "same source opening
        connections at a very high rate, repeatedly" -- confirmed live
        2026-08-20/21: an hping3 SYN flood was reliably caught by the
        binary model (an attack, something) but the multiclass model
        couldn't name it, falling back to the generic ATTACK label with
        no MITRE mapping and severity capped at MEDIUM (attack-type-keyed
        lookups have nothing to match).

        "dos_flagged" is populated by _run_live()'s main loop from
        core.flow_collector.FlowCollector.connection_rate() (needs
        cross-flow history the per-chunk DataFrame alone doesn't have) --
        this is a no-op in simulate mode, where the column is simply
        absent, same defensive pattern _run_beacon() already uses for
        beacon_detected.

        Naive fixed-rate threshold, tuned against this lab's own hping3
        capture -- not validated against production-scale legitimate
        traffic, and defeated by an attacker who deliberately throttles
        below it. See
        docs/superpowers/specs/2026-08-23-dos-ddos-multiclass-retrain-design.md
        for the disclosed limitation and the production-readiness
        follow-up (adaptive, baseline-relative thresholding) this doesn't
        attempt to solve.

        Lower confidence (0.75) than an exact signature match (0.90),
        same reasoning as _run_beacon(): this is a statistical inference
        over connection rate, not an exact pattern hit.
        """
        if "dos_flagged" not in chunk.columns:
            return chunk
        dos_mask = chunk["dos_flagged"].fillna(False).astype(bool)
        if not dos_mask.any():
            return chunk

        chunk = chunk.copy()
        if "sig_attack_type" not in chunk.columns:
            chunk["sig_attack_type"] = None
        # Don't override a more specific payload-signature match on the
        # same flow -- same precedence beacon detection already uses
        # relative to Layer 2 signatures.
        newly_labelled = chunk["sig_attack_type"].isna() & dos_mask
        if not newly_labelled.any():
            return chunk
        chunk.loc[newly_labelled, "sig_attack_type"] = "DoS"
        if "pred_binary" in chunk.columns:
            chunk.loc[newly_labelled, "pred_binary"] = 1
        else:
            chunk["pred_binary"] = newly_labelled.astype(int)
        if "confidence" in chunk.columns:
            chunk.loc[newly_labelled, "confidence"] = \
                chunk.loc[newly_labelled, "confidence"].clip(lower=0.75)
        else:
            chunk.loc[newly_labelled, "confidence"] = 0.75
        return chunk
```

- [ ] **Step 4: Wire `_run_dos()` into the pipeline, right after `_run_beacon()`**

At `sentinel.py:304` (`chunk = self._run_beacon(chunk)`), add immediately after:

```python
        chunk = self._run_beacon(chunk)
        chunk = self._run_dos(chunk)
```

- [ ] **Step 5: Run test to verify Checks 4-5 pass**

Run: `python lab/verify_dos_detection.py`
Expected: five `PASS` lines, then `All checks passed.` (Checks 4-5 call `_run_dos()` directly on a synthetic chunk, not through the live loop, so they don't need `_add_dos_column()` — that's added next, in Step 6.)

- [ ] **Step 6: Add `_add_dos_column()` to `sentinel.py`'s live loop**

Insert directly after `_add_beacon_column()` (which ends at line 1125):

```python

    def _add_dos_column(flow_df: pd.DataFrame) -> pd.DataFrame:
        """Cross-flow connection rate needs FlowCollector's connection
        history, which only exists here (not inside
        SentinelIPS.process_chunk(), which only ever sees one chunk at a
        time) -- queried once per unique (src,dst) pair in this chunk,
        same pattern as _add_beacon_column()."""
        if "src_ip" not in flow_df.columns or "dst_ip" not in flow_df.columns:
            return flow_df
        pairs = flow_df[["src_ip", "dst_ip"]].drop_duplicates()
        dos_map = {
            (s, d): collector.connection_rate(s, d)["is_flood"]
            for s, d in pairs.itertuples(index=False)
        }
        flow_df["dos_flagged"] = [
            dos_map.get((s, d), False)
            for s, d in zip(flow_df["src_ip"], flow_df["dst_ip"])
        ]
        return flow_df
```

- [ ] **Step 7: Call `_add_dos_column()` at both call sites `_add_beacon_column()` has**

At `sentinel.py:1138` (inside the main loop):

```python
                flow_df = _add_beacon_column(flow_df)
                flow_df = _add_dos_column(flow_df)
```

At `sentinel.py:1154` (inside the `KeyboardInterrupt` flush):

```python
            final_df = _add_beacon_column(eng.transform(final_df))
            final_df = _add_dos_column(final_df)
```

- [ ] **Step 8: Run the full test one more time to confirm nothing broke**

Run: `python lab/verify_dos_detection.py`
Expected: five `PASS` lines, then `All checks passed.`

- [ ] **Step 9: Run the project's established health check**

Run: `python sentinel.py health`
Expected: `OK  : 33/33`, pipeline wiring check passes, exit code 0. (Module count stays 33 — no new module file was added, only two existing files were modified.)

- [ ] **Step 10: Commit**

```bash
git add sentinel.py lab/verify_dos_detection.py
git commit -m "feat: add rule-based DoS override, mirroring Bot/beacon detection"
```
