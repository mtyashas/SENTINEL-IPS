# Tier 3 Attack Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Exfiltration and Session Hijacking detection (both currently
undetected — real gaps, not misclassified into something else), and surface
the already-working but never-displayed APT/Insider attribution data in the
dashboard.

**Architecture:** Exfiltration is a single-flow byte-volume threshold check
in `sentinel.py`, mirroring `_run_dos()`'s rule-based-override structure but
needing no new cross-flow state. Session Hijacking is new state inside
`detection/layer2_signatures.py`'s `SignatureDetector` (session token → last
seen source IP), reusing the cookie-extraction logic `check_csrf()` already
has and the same session-invalidation response path. APT/Insider surfacing
adds two already-computed fields to the existing dashboard event payload —
no new detection logic.

**Tech Stack:** Python, `pandas`, existing `SignatureDetector`/`SentinelIPS`
classes, `collections.OrderedDict` (stdlib, for bounded session-history
eviction).

**Spec:** `docs/superpowers/specs/2026-08-24-tier3-attack-detection-design.md`

## Global Constraints

- No new files in `core/` — Exfiltration needs no new cross-flow state.
- `_EXFIL_BYTES_THRESHOLD = 5_000_000` (5MB combined fwd+bwd bytes/flow), confidence floor 0.60.
- `_SESSION_HISTORY_MAX_ENTRIES = 500`, Session Hijacking confidence floor 0.70.
- Both new attack types get `action=log`-first responses (Exfiltration) or
  the existing CSRF-style session-invalidation response (Session Hijacking)
  — neither auto-blocks an IP, for the reasons in the spec (blunt heuristic /
  src_ip may be the legitimate user).
- Ransomware is explicitly out of scope this round — see spec's "deferred" section. Do not add a Ransomware detector as part of this plan.
- Every new check gets a `lab/verify_*.py` script mirroring the existing `lab/verify_dos_detection.py`/`lab/verify_beacon_detection.py` pattern (synthetic inputs, positive + negative case, no live capture needed).

---

## File Structure

```
detection/layer2_signatures.py    MODIFIED — factor cookie extraction out of
                                   check_csrf() into a module-level
                                   _extract_session_cookie() helper; add
                                   check_session_hijack(); add
                                   self._session_last_ip OrderedDict state

sentinel.py                       MODIFIED — add _run_exfil(); wire
                                   check_session_hijack() into
                                   _run_signatures(); extend the existing
                                   CSRF-only branches in _build_event() and
                                   _run_response() to also cover Session
                                   Hijacking; add actor_class/sophistication
                                   to the dashboard event payload

config.py                         MODIFIED — add "Exfiltration" and
                                   "Session Hijacking" to RESPONSE_MATRIX
                                   and SEVERITY_LEVELS

lab/
├── verify_exfil_detection.py     NEW
└── verify_session_hijack.py      NEW
```

---

### Task 1: Exfiltration detection

**Files:**
- Modify: `sentinel.py` (add `_run_exfil()` after `_run_dos()`, which ends
  around line 660 post-tonight's-earlier-edits — locate by searching for
  `def _run_dos`; wire the call in `process_chunk()` after the existing
  `chunk = self._run_dos(chunk)` line)
- Modify: `config.py` (add `"Exfiltration"` to `RESPONSE_MATRIX` and
  `SEVERITY_LEVELS["MEDIUM"]`)
- Create: `lab/verify_exfil_detection.py`

**Interfaces:**
- Produces: `SentinelIPS._run_exfil(self, chunk: pd.DataFrame) -> pd.DataFrame`

- [ ] **Step 1: Write the failing test**

```python
"""
lab/verify_exfil_detection.py

Purpose: Self-check for rule-based Exfiltration detection (2026-08-24).
         Unlike DoS/Beacon, this needs no cross-flow state -- a single
         flow's own byte-count features (total_length_of_fwd_packets /
         total_length_of_bwd_packets, already computed by FlowCollector
         for every flow, live or simulated) are sufficient signal on
         their own. Confirms: (1) a flow whose combined transferred bytes
         cross _EXFIL_BYTES_THRESHOLD gets flagged, (2) an ordinary small
         flow doesn't, (3) a flow that already has a more specific
         signature match (e.g. SQLInjection) keeps that label instead of
         being overridden -- Exfiltration is the lowest-confidence
         rule-based override (0.60) and must never steal a more specific
         detection's label.

Usage:
    python lab/verify_exfil_detection.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd

from sentinel import SentinelIPS

ips = SentinelIPS()  # no model_path needed -- _run_exfil never touches layer1

print("--- Check 1: a flow whose combined bytes cross the threshold is flagged Exfiltration ---")
chunk = pd.DataFrame({
    "total_length_of_fwd_packets": [100.0, 6_000_000.0],
    "total_length_of_bwd_packets": [200.0, 500_000.0],
})
result = ips._run_exfil(chunk)
assert pd.isna(result.iloc[0]["sig_attack_type"]), f"FAIL: small flow should be untouched: {result.iloc[0]}"
assert result.iloc[1]["sig_attack_type"] == "Exfiltration", f"FAIL: large flow not flagged: {result.iloc[1]}"
assert result.iloc[1]["pred_binary"] == 1
assert result.iloc[1]["confidence"] >= 0.60
print(f"PASS: large-transfer row -> sig_attack_type=Exfiltration, confidence={result.iloc[1]['confidence']:.2f}; "
      f"small row untouched")

print()
print("--- Check 2: a flow with an existing, more specific signature match keeps that label ---")
chunk2 = pd.DataFrame({
    "total_length_of_fwd_packets": [8_000_000.0],
    "total_length_of_bwd_packets": [0.0],
    "sig_attack_type":             ["SQLInjection"],
})
result2 = ips._run_exfil(chunk2)
assert result2.iloc[0]["sig_attack_type"] == "SQLInjection", \
    f"FAIL: Exfiltration must not override an existing, more specific label: {result2.iloc[0]}"
print("PASS: existing SQLInjection label preserved, not overridden by the lower-confidence Exfiltration check")

print()
print("--- Check 3: chunk with neither byte-count column (unexpected schema) is a no-op ---")
chunk3 = pd.DataFrame({"src_ip": ["1.2.3.4"]})
result3 = ips._run_exfil(chunk3)
assert "sig_attack_type" not in result3.columns
assert result3.equals(chunk3)
print("PASS: chunk without byte-count columns passed through untouched")

print()
print("All checks passed.")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python lab/verify_exfil_detection.py`
Expected: `AttributeError: 'SentinelIPS' object has no attribute '_run_exfil'`

- [ ] **Step 3: Add `_run_exfil()` to `sentinel.py`**

Insert directly after `_run_dos()` (search for `def _run_dos`, insert after
its closing `return chunk`):

```python

    def _run_exfil(self, chunk: pd.DataFrame) -> pd.DataFrame:
        """
        Rule-based large-transfer detection. Unlike DoS/Beacon, this needs
        no cross-flow state -- a single flow's own byte-count features
        (already computed by FlowCollector for every flow, live or
        simulated) are sufficient signal on their own.

        Naive threshold, deliberately lower confidence (0.60) than an exact
        signature match (0.90) or even the rate-based DoS/Beacon overrides
        (0.75): total bytes transferred alone can't distinguish data theft
        from an ordinary bulk download or backup job. This is a "flag for
        review" signal (action=log, no auto-block), not a high-confidence
        verdict.

        Known limitation: this runs after process_chunk()'s own
        self-traffic exclusion filter (added 2026-08-24), which drops any
        flow where src_ip matches the protected server's own IP -- so a
        compromised server exfiltrating its own data outward is currently
        invisible to this check, since that traffic has exactly the shape
        the noise filter was built to suppress. Not fixed here: doing so
        needs the self-traffic filter to distinguish ordinary self-noise
        from an unusually large self-originated transfer, its own
        threshold-tuning problem. This check does catch the more common
        testable case instead: an external attacker pulling a large volume
        of data FROM the server.
        """
        fwd_col, bwd_col = "total_length_of_fwd_packets", "total_length_of_bwd_packets"
        if fwd_col not in chunk.columns and bwd_col not in chunk.columns:
            return chunk

        total_bytes = chunk.get(fwd_col, 0).fillna(0) + chunk.get(bwd_col, 0).fillna(0)
        exfil_mask = total_bytes >= _EXFIL_BYTES_THRESHOLD
        if not exfil_mask.any():
            return chunk

        chunk = chunk.copy()
        if "sig_attack_type" not in chunk.columns:
            chunk["sig_attack_type"] = None
        # Exfiltration is the lowest-confidence rule-based override -- never
        # steal a more specific detection's label, same precedence pattern
        # beacon/DoS already use.
        newly_labelled = chunk["sig_attack_type"].isna() & exfil_mask
        if not newly_labelled.any():
            return chunk
        chunk.loc[newly_labelled, "sig_attack_type"] = "Exfiltration"
        if "pred_binary" in chunk.columns:
            chunk.loc[newly_labelled, "pred_binary"] = 1
        else:
            chunk["pred_binary"] = newly_labelled.astype(int)
        if "confidence" in chunk.columns:
            chunk.loc[newly_labelled, "confidence"] = \
                chunk.loc[newly_labelled, "confidence"].clip(lower=0.60)
        else:
            chunk.loc[newly_labelled, "confidence"] = 0.60
        return chunk
```

Add the threshold constant near the top of `sentinel.py`, alongside any
similar module-level constants (search for where other simple module-level
config values live, e.g. near imports/top-level constants):

```python
_EXFIL_BYTES_THRESHOLD = 5_000_000   # 5MB combined fwd+bwd bytes per flow
```

- [ ] **Step 4: Wire `_run_exfil()` into the pipeline**

In `process_chunk()`, immediately after the existing
`chunk = self._run_dos(chunk)` line and before `_run_anomaly`:

```python
        chunk = self._run_dos(chunk)
        chunk = self._run_exfil(chunk)

        # --- Layer 3: anomaly detection (fit on first non-trivial chunk) ---
```

- [ ] **Step 5: Add config entries**

In `config.py`'s `RESPONSE_MATRIX`, add right after the `"CSRF"` entry:

```python
    "Exfiltration": ["log", "alert_medium"],
```

In `config.py`'s `SEVERITY_LEVELS["MEDIUM"]` list, add `"Exfiltration"`:

```python
    "MEDIUM":   ["BruteForce", "SQLInjection", "XSS", "CSRF", "Exfiltration"],
```

- [ ] **Step 6: Run test to verify it passes**

Run: `python lab/verify_exfil_detection.py`
Expected: three `PASS` lines, then `All checks passed.`

- [ ] **Step 7: Run health check**

Run: `python sentinel.py health`
Expected: `OK : 33/33`, pipeline wiring clean.

- [ ] **Step 8: Commit**

```bash
git add sentinel.py config.py lab/verify_exfil_detection.py
git commit -m "feat: add rule-based Exfiltration detection (single-flow byte threshold)"
```

---

### Task 2: Session Hijacking detection

**Files:**
- Modify: `detection/layer2_signatures.py` (factor out cookie extraction,
  add `check_session_hijack()`, add instance state)
- Modify: `sentinel.py` (wire the new check into `_run_signatures()`; extend
  the CSRF-only branches in `_build_event()` and `_run_response()`)
- Modify: `config.py` (add `"Session Hijacking"` to `RESPONSE_MATRIX` and
  `SEVERITY_LEVELS["MEDIUM"]`)
- Create: `lab/verify_session_hijack.py`

**Interfaces:**
- Consumes: nothing from Task 1 — independent.
- Produces: `SignatureDetector.check_session_hijack(self, raw_request: str, src_ip: str) -> Dict` — same return shape as `check_csrf()` (`detected`, `attack_type`, `pattern_matched`, `severity`, MITRE fields, plus `session_token` when detected).

- [ ] **Step 1: Write the failing test**

```python
"""
lab/verify_session_hijack.py

Purpose: Self-check for Session Hijacking detection (2026-08-24).
         detection.layer2_signatures.SignatureDetector.check_session_hijack()
         tracks which source IP a session cookie was last seen from --
         reusing check_csrf()'s existing cookie-extraction logic rather
         than duplicating it. Confirms: (1) the same session cookie from
         the same IP twice in a row is never flagged (normal repeat
         traffic), (2) the same session cookie appearing from a NEW IP is
         flagged, and the response carries the session_token needed for
         invalidation, (3) a request with no session cookie at all is a
         clean no-op, (4) the bounded history evicts its oldest entry once
         _SESSION_HISTORY_MAX_ENTRIES is exceeded, so this can't grow
         unbounded on a long-running server.

Usage:
    python lab/verify_session_hijack.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from detection.layer2_signatures import SignatureDetector

def make_request(session_id: str) -> str:
    return (
        f"GET /dashboard HTTP/1.1\r\n"
        f"Host: 192.168.0.104\r\n"
        f"Cookie: session={session_id}\r\n"
        f"\r\n"
    )

print("--- Check 1: same session cookie, same IP, twice -- never flagged ---")
sig = SignatureDetector()
req = make_request("abc123")
first = sig.check_session_hijack(req, "192.168.0.10")
second = sig.check_session_hijack(req, "192.168.0.10")
assert not first["detected"], f"FAIL: first sighting of a session should never be flagged: {first}"
assert not second["detected"], f"FAIL: same IP repeating should not be flagged: {second}"
print("PASS: first sighting and same-IP repeat both correctly NOT flagged")

print()
print("--- Check 2: same session cookie, different IP -- flagged, carries session_token ---")
hijack = sig.check_session_hijack(req, "203.0.113.99")
assert hijack["detected"], f"FAIL: session cookie switching IPs should be flagged: {hijack}"
assert hijack["attack_type"] == "Session Hijacking"
assert hijack["session_token"] == "abc123"
print(f"PASS: IP switch on an existing session correctly flagged -> session_token={hijack['session_token']!r}")

print()
print("--- Check 2b: the SAME new IP repeating right after is not re-flagged (only the transition fires) ---")
repeat = sig.check_session_hijack(req, "203.0.113.99")
assert not repeat["detected"], f"FAIL: the new IP's own follow-up requests should not re-trigger: {repeat}"
print("PASS: only the transition moment was flagged, not every subsequent request from the new IP")

print()
print("--- Check 3: request with no session cookie is a clean no-op ---")
no_cookie_req = "GET /health HTTP/1.1\r\nHost: 192.168.0.104\r\n\r\n"
result3 = sig.check_session_hijack(no_cookie_req, "192.168.0.10")
assert not result3["detected"]
print("PASS: request with no session cookie correctly NOT flagged")

print()
print("--- Check 4: bounded history evicts the oldest entry past _SESSION_HISTORY_MAX_ENTRIES ---")
from detection.layer2_signatures import _SESSION_HISTORY_MAX_ENTRIES
sig2 = SignatureDetector()
sig2.check_session_hijack(make_request("first-session"), "10.0.0.1")
for i in range(_SESSION_HISTORY_MAX_ENTRIES):
    sig2.check_session_hijack(make_request(f"filler-{i}"), "10.0.0.2")
assert "first-session" not in sig2._session_last_ip, \
    "FAIL: oldest entry should have been evicted once the history exceeded its cap"
assert len(sig2._session_last_ip) <= _SESSION_HISTORY_MAX_ENTRIES
print(f"PASS: history correctly bounded at {_SESSION_HISTORY_MAX_ENTRIES} entries, oldest evicted")

print()
print("All checks passed.")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python lab/verify_session_hijack.py`
Expected: `AttributeError: 'SignatureDetector' object has no attribute 'check_session_hijack'`

- [ ] **Step 3: Factor out the shared cookie-extraction helper**

In `detection/layer2_signatures.py`, add this module-level function near the
other module-level helpers (`_no_detection`/`_detection` — search for `def _detection`, add just before or after it):

```python
def _extract_session_cookie(raw_request: str) -> Optional[str]:
    """
    Pull the session-identifying cookie value out of a raw HTTP request,
    shared by check_csrf() and check_session_hijack() so the extraction
    logic exists in exactly one place.

    Falls back to the whole Cookie header when no cookie is specifically
    named "session" -- still a usable opaque identifier, just less precise
    than the named case.
    """
    cookie_match = _CSRF_COOKIE_RE.search(raw_request)
    if not cookie_match:
        return None
    cookie_header = cookie_match.group(1).strip()
    session_match = _CSRF_SESSION_COOKIE_RE.search(cookie_header)
    return session_match.group(1) if session_match else cookie_header
```

Then simplify `check_csrf()` (search for `def check_csrf`) — replace:

```python
        cookie_match = _CSRF_COOKIE_RE.search(raw_request)
        if not cookie_match:
            return _no_detection()   # no session to forge -- nothing at risk
        cookie_header = cookie_match.group(1).strip()
        session_match = _CSRF_SESSION_COOKIE_RE.search(cookie_header)
        # Falls back to the whole Cookie header when no cookie is
        # specifically named "session" -- still a usable opaque identifier
        # for invalidation, just not as precise as the named-cookie case.
        session_token = session_match.group(1) if session_match else cookie_header
```

with:

```python
        session_token = _extract_session_cookie(raw_request)
        if session_token is None:
            return _no_detection()   # no session to forge -- nothing at risk
```

- [ ] **Step 4: Add the bounded state and `check_session_hijack()`**

Add the import and constant near the top of the file (alongside the other
`_CSRF_*` constants, search for `_CSRF_ORIGIN_RE`):

```python
from collections import OrderedDict
```

(add to the existing `import` block at the top of the file, not inline)

```python
_SESSION_HISTORY_MAX_ENTRIES = 500   # bounds self._session_last_ip's growth
                                      # on a long-running server -- same class
                                      # of concern _conn_history's bounded
                                      # deques already address for beacon/DoS
                                      # in core/flow_collector.py.
```

In `SignatureDetector.__init__` (search for `def __init__`), add after the
existing regex-compilation block, before the closing `logger.info(...)` call:

```python
        # session token -> last source IP seen using it, for
        # check_session_hijack(). Bounded/LRU-evicted via OrderedDict, not a
        # plain dict, so a long-running server's session history doesn't
        # grow forever.
        self._session_last_ip: "OrderedDict[str, str]" = OrderedDict()
```

Add the new method directly after `check_csrf()` (search for the end of
`check_csrf()`, right before `def scan`):

```python

    def check_session_hijack(self, raw_request: str, src_ip: str) -> Dict:
        """
        Detect an existing session cookie suddenly being used from a
        different source IP -- the classic signature of a stolen or
        replayed session token. Unlike check_csrf() (a structural
        header-mismatch check, not tied to a specific cookie value), this
        tracks *continuity*: the same session token seen from a new src_ip
        it wasn't previously bound to.

        Checked against every request carrying a session cookie, not just
        state-changing requests to sensitive paths (check_csrf()'s scope)
        -- hijacking is meaningful on any authenticated request, not just
        ones that change state.

        Known limitation, same class as beacon_score()'s/connection_rate()'s
        own heuristics: a real client switching networks mid-session (WiFi
        to mobile) produces an identical signature to a stolen cookie -- no
        way to distinguish the two from network-layer data alone. Behind a
        NAT/proxy chain, the src_ip this sees may not be the true client IP
        either.

        Inputs:  raw_request -- full raw HTTP request text (payload_sample)
                 src_ip -- the flow's source IP
        Outputs: detection dict, plus "session_token" when detected (same
                 field CSRF uses -- the response is identical: invalidate
                 the session, never block src_ip, since src_ip here might
                 be the legitimate user who just changed networks, not the
                 thief)
        """
        session_token = _extract_session_cookie(raw_request)
        if session_token is None:
            return _no_detection()

        last_ip = self._session_last_ip.get(session_token)
        self._session_last_ip[session_token] = src_ip
        self._session_last_ip.move_to_end(session_token)
        if len(self._session_last_ip) > _SESSION_HISTORY_MAX_ENTRIES:
            self._session_last_ip.popitem(last=False)

        if last_ip is None or last_ip == src_ip:
            return _no_detection()   # first sighting, or same IP as before

        result = _detection("Session Hijacking",
                             f"session cookie switched from {last_ip} to {src_ip}")
        result["session_token"] = session_token
        return result
```

- [ ] **Step 5: Run test to verify Checks 1-4 pass**

Run: `python lab/verify_session_hijack.py`
Expected: `AttributeError` is gone, but this step's checks only exercise
`SignatureDetector` directly, not `sentinel.py`'s wiring — expect all of
Checks 1-4 to now pass (five `PASS` lines total, then `All checks passed.`).

- [ ] **Step 6: Wire into `sentinel.py`'s `_run_signatures()`**

Search for `def _run_signatures`. Add `has_src_ip = "src_ip" in chunk.columns`
next to the existing `has_dst_ip = "dst_ip" in chunk.columns` line:

```python
            has_dst_ip = "dst_ip" in chunk.columns
            has_src_ip = "src_ip" in chunk.columns
```

Then insert a new check between the existing CSRF block and the
`check_payload` fallback chain (search for `csrf_hit = self._sig.check_csrf(payload)` and its `continue`, insert immediately after):

```python
                csrf_hit = self._sig.check_csrf(payload)
                if csrf_hit["detected"]:
                    sig_types.at[idx]   = csrf_hit["attack_type"]
                    csrf_tokens.at[idx] = csrf_hit.get("session_token", "")
                    continue

                if has_src_ip:
                    hijack_hit = self._sig.check_session_hijack(
                        payload, chunk.at[idx, "src_ip"])
                    if hijack_hit["detected"]:
                        sig_types.at[idx]   = hijack_hit["attack_type"]
                        csrf_tokens.at[idx] = hijack_hit.get("session_token", "")
                        continue

                hit = self._sig.check_payload(payload)
```

(The `csrf_tokens` column is intentionally reused for both attack types —
`_build_event()`/`_run_response()` need the same `session_token` field for
both, see Step 7.)

- [ ] **Step 7: Extend the CSRF-only branches to cover Session Hijacking too**

In `_build_event()` (search for `if attack_type == "CSRF":`), change to:

```python
            if attack_type in ("CSRF", "Session Hijacking"):
                # The response layer needs this to invalidate the affected
                # session instead of blocking src_ip -- for CSRF, src_ip is
                # the victim's browser; for Session Hijacking, src_ip might
                # be the legitimate user who just changed networks, not the
                # thief. Neither should ever be IP-blocked on this signal
                # alone.
                event["session_token"] = str(row.get("csrf_session_token", ""))
```

In `_run_response()` (search for `if attack == "CSRF":`), change to:

```python
        if attack in ("CSRF", "Session Hijacking"):
            # Neither attack type's src_ip is safe to block: a CSRF
            # request's src_ip is the victim's own browser, and a session
            # hijack's src_ip might just as easily be the legitimate user
            # who changed networks as the actual thief. The correct
            # countermeasure for both is session-level: kill the affected
            # session token so it (and any further replay) stops being
            # accepted, then alert. No IP block, ever, for either.
```

(keep the existing body of the branch unchanged — only the condition and
comment change).

- [ ] **Step 8: Add config entries**

In `config.py`'s `RESPONSE_MATRIX`, add right after the (now two-entry)
CSRF/Exfiltration additions from Task 1:

```python
    "Session Hijacking": ["invalidate_session", "alert_medium"],
```

In `config.py`'s `SEVERITY_LEVELS["MEDIUM"]` list, add `"Session Hijacking"`
alongside `"Exfiltration"` from Task 1:

```python
    "MEDIUM":   ["BruteForce", "SQLInjection", "XSS", "CSRF", "Exfiltration", "Session Hijacking"],
```

- [ ] **Step 9: Run test to verify all checks pass**

Run: `python lab/verify_session_hijack.py`
Expected: seven `PASS` lines, then `All checks passed.`

- [ ] **Step 10: Run the full regression suite**

```bash
python lab/verify_dos_detection.py
python lab/verify_beacon_detection.py
python lab/verify_self_traffic_exclusion.py
python lab/verify_exfil_detection.py
python lab/verify_session_hijack.py
python sentinel.py health
```

Expected: every script prints `All checks passed.` (or, for `health`,
`OK : 33/33` with clean pipeline wiring) — confirms the `check_csrf()`
refactor in Step 3 didn't regress CSRF detection itself.

- [ ] **Step 11: Commit**

```bash
git add detection/layer2_signatures.py sentinel.py config.py lab/verify_session_hijack.py
git commit -m "feat: add Session Hijacking detection via session-cookie/IP continuity tracking"
```

---

### Task 3: Surface APT/Insider attribution in the dashboard

**Files:**
- Modify: `sentinel.py` (confirm `actor_class`/`sophistication` reach the
  dashboard event payload — check `dashboard/server.py`'s emitted event
  shape first, since this task's exact diff depends on what that payload
  currently includes)

**Interfaces:**
- Consumes: `event["actor_class"]`, `event["sophistication"]` — already set
  by `sentinel.py`'s existing `_run_attribution` step (see spec; no change
  needed to produce these, only to make sure they're not dropped before
  reaching the dashboard).

- [ ] **Step 1: Locate the dashboard event payload**

Run: `grep -n "dashboard_update\|emit(" dashboard/server.py | head -20`

Read the function that builds the per-detection event payload sent over
Socket.IO (likely named something like `_serialize_event` or built inline
in a `record_detection`/`push_event` call). Confirm whether it passes the
full `event` dict through as-is (in which case `actor_class`/
`sophistication` are *already* present in the payload and this task is a
documentation/dashboard-frontend task, not a backend one) or whether it
explicitly whitelists fields (in which case add `"actor_class"` and
`"sophistication"` to that whitelist).

- [ ] **Step 2: If fields are being dropped, add them explicitly**

If Step 1 finds an explicit field whitelist/allowlist that excludes
`actor_class`/`sophistication`, add both keys there, pulling from the same
`event` dict already flowing through `sentinel.py`'s detection pipeline —
no new computation, just don't drop these two keys.

- [ ] **Step 3: Verify with a manual dashboard check**

Run `sentinel.py live` (or `simulate`) briefly, open the dashboard, and
confirm `actor_class`/`sophistication` appear somewhere in the alert
stream's per-event detail (exact UI placement is a frontend call — a
tooltip, an extra column, or a badge next to the attack type are all
reasonable; don't design a new panel for this, YAGNI). This step is
manual/visual — no automated check is meaningful for "is this rendered
somewhere a human can see it."

- [ ] **Step 4: Commit**

```bash
git add sentinel.py dashboard/
git commit -m "feat: surface APT/Insider actor classification in the dashboard event stream"
```
