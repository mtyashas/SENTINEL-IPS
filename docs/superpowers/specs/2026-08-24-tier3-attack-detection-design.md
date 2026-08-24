# Tier 3 Attack Detection — Design Spec

**Date:** 2026-08-24
**Status:** Approved by council review; built autonomously while the user was away, for review on return.

## Context

During tonight's live multi-host test, the user asked for a full attack-coverage
audit. Initial pass (in-conversation, not written down formally) classified
Ransomware, APT, Exfiltration, Session Hijacking, and Insider as "Tier 3 —
no detector code exists." On investigation, that classification was wrong for
two of the five:

- **APT** and **Insider** are already fully implemented:
  `attribution/threat_profiler.py`'s `ThreatActorProfiler` classifies every
  attacker as APT/Organised/ScriptKiddie/Insider using real signal
  (multi-tactic behaviour, lateral movement, persistence, slow tempo, port
  diversity, VPN/proxy use → APT; private IP + auth failures + low port
  diversity → Insider), and it's already wired into `sentinel.py`'s main
  pipeline (`_run_attribution`, ingesting every detection event). Verified
  against tonight's real attacker profiles in
  `threat_intel/attacker_profiles.jsonl`: brindha's 847-event port scan
  correctly scored `ScriptKiddie` (score 20) — the profiler is producing
  sensible verdicts on real data. The actual gap: `event["actor_class"]` and
  `event["sophistication"]` are computed on every event but never referenced
  anywhere in `dashboard/` — genuinely dead output, not a missing detector.

This spec covers what's actually new: **Exfiltration**, **Session
Hijacking**, and **dashboard surfacing for APT/Insider**. It also documents
why **Ransomware** is deliberately deferred rather than built as a hollow
heuristic.

## Council review

- **Dr. Sentinel:** No CIC-IDS-2017 class exists for Exfiltration, Session
  Hijacking, or Ransomware — none of these can be a multiclass retrain
  target. Rule-based overrides are the only honest option, same pattern as
  tonight's DoS/Beacon work.
- **Vector:** Exfiltration doesn't need new cross-flow state like DoS/Beacon
  did — a single flow's own byte-count features (already computed by
  `FlowCollector`) are sufficient signal on their own.
- **Ghost:** Session hijacking's real tell is a session cookie suddenly used
  from a different source IP — `detection/layer2_signatures.py` already
  parses cookies for CSRF; reuse that, don't reinvent it.
- **Cipher / Prism:** Ransomware's only credible network-visible signal (mass
  SMB file-share writes) needs an SMB/file-share target in the lab to
  generate traffic against — this lab only has an HTTP target service.
  Building a detector with zero ability to be exercised against real traffic
  here is exactly the "toy implementation" the project rules forbid.
  **Decision: defer, document the real scope, don't fake it.**

## Feature 1: Exfiltration

**Mechanism:** Single-flow byte-volume threshold — no new cross-flow state
needed. `core/flow_collector.py` already computes `total_length_of_fwd_packets`
and `total_length_of_bwd_packets` per flow. A new `sentinel.py._run_exfil()`
pipeline stage (mirroring `_run_dos()`'s structure) flags any flow whose
combined transferred bytes exceed `_EXFIL_BYTES_THRESHOLD` (default 5,000,000
— 5MB, chosen as clearly above ordinary API/web-page traffic without being so
low that any moderate file transfer trips it). Sets `sig_attack_type =
"Exfiltration"` at MEDIUM confidence (0.60) — deliberately lower than DoS/
Beacon's 0.75 floor, since "large transfer" alone is a much weaker signal than
a rate-based or payload-based match; a real bulk download or backup job looks
identical to data theft under this heuristic alone.

**Known limitation, disclosed not hidden:** this only sees flows that survive
`process_chunk()`'s self-traffic-exclusion filter (added earlier tonight,
2026-08-24, to kill false-positive noise from this laptop's own outbound
traffic). That filter drops any flow where `src_ip` matches the protected
server's own IP — which means **a compromised server exfiltrating its own
data outward would currently be invisible to this check**, since that
traffic has exactly the `src_ip == self` shape the noise filter was built to
suppress. This is a real gap, not swept under the rug: fixing it properly
needs the self-traffic filter to distinguish "ordinary self-noise" from
"unusually large self-originated transfer" rather than a blanket exclusion —
scoped as a follow-up, not attempted in this pass, because it needs its own
threshold-tuning work to avoid reintroducing tonight's noise problem.
Tonight's realistic testable scenario is the more common one anyway: an
external attacker pulling a large volume of data *from* the server, which
this check does catch (flow's `src_ip` is the attacker, uninvolved with the
self-traffic filter).

**Response:** `action=log` only, no auto-block — a byte-count-only heuristic
is too blunt an instrument to justify blocking a source automatically; this
is a "flag for review" signal, matching how the codebase already treats other
low-precision signals (PortScan's LOW severity, no auto-block).

## Feature 2: Session Hijacking

**Mechanism:** New state inside `detection/layer2_signatures.py`'s
`SignatureDetector` (not `FlowCollector` — the cookie-parsing logic already
lives here for `check_csrf()`, so the state belongs where the data already
gets extracted, not duplicated into a lower layer). `check_csrf()`'s cookie
extraction (`_CSRF_COOKIE_RE`/`_CSRF_SESSION_COOKIE_RE`) currently only runs
when the request is state-changing *and* hits a CSRF-sensitive path — session
hijacking needs to check *every* request that carries a session cookie, not
just those. Factor the extraction into a shared helper, call it from a new
`check_session_hijack(raw_request, src_ip)` method.

`SignatureDetector` is currently stateless (compiled regexes only, no
instance state) — this is the first check that needs memory across calls.
Confirmed safe to add without locking: `_run_signatures()` is only ever
called from `process_chunk()`'s single-threaded main loop, never
concurrently (unlike `FlowCollector`, which needed `self._lock` because
packet ingestion runs on a separate capture thread).

New state: `self._session_last_ip: OrderedDict[str, str]` — session token →
the last source IP seen using it. `OrderedDict` (stdlib, no new dependency)
so old entries can be evicted LRU-style once `_SESSION_HISTORY_MAX_ENTRIES`
(default 500) is exceeded, bounding memory on a long-running server — the
same class of concern `_conn_history`'s bounded deques already address for
beacon/DoS state, applied here since a plain unbounded dict would grow
forever on a real server.

Logic: no entry for this token yet → record it, no detection (first sighting
of this session). Entry exists and matches `src_ip` → no detection (normal).
Entry exists and differs from `src_ip` → detection (`sig_attack_type =
"Session Hijacking"`, confidence 0.70), then update the entry to the new IP
so the *next* request from that IP doesn't re-fire — only the transition
moment is flagged.

**Known limitation, disclosed not hidden:** a real client switching networks
mid-session (WiFi to mobile data) produces the exact same signature as a
stolen/replayed cookie — this is a real false-positive source with no way to
distinguish the two from network-layer data alone. Same class of caveat as
`beacon_score()`'s and `connection_rate()`'s own documented heuristic limits.
Also: if SENTINEL sits behind a NAT/proxy chain, the `src_ip` it sees may not
be the true client IP, which would either mask real hijacking (all clients
share one apparent IP) or falsely trigger on legitimate different clients
sharing session state through a shared connection — not addressed here,
consistent with the project's existing IP-based model.

**Response:** Reuses the existing CSRF response path
(`ConnectionTerminator.invalidate_session()`), not IP blocking — for the same
reason CSRF doesn't block IPs: the request coming in is from whoever now
holds the session token, and the fix is killing the session, not blocking a
source that might be the legitimate user.

## Feature 3: APT / Insider dashboard surfacing

**Mechanism:** No new detection logic — `ThreatActorProfiler` already works.
Add `actor_class` and `sophistication` to whatever event payload
`dashboard/server.py` already emits per detection (the existing
`dashboard_update` Socket.IO event), and surface it in the existing alert
stream / threat-intel feed panel rather than building a new dashboard view —
YAGNI: the data just needs to be visible, not a new visualization built
around it tonight.

## File structure changes

```
core/flow_collector.py            unchanged — Exfiltration doesn't need new
                                   cross-flow state, only existing per-flow
                                   byte-count fields

detection/layer2_signatures.py    MODIFIED — factor cookie extraction out of
                                   check_csrf() into a shared helper; add
                                   check_session_hijack(); add
                                   self._session_last_ip state + its
                                   OrderedDict eviction constant

sentinel.py                       MODIFIED — add _run_exfil() (mirrors
                                   _run_dos()'s structure exactly); wire
                                   check_session_hijack() into
                                   _run_signatures() alongside the existing
                                   check_csrf() call; add actor_class/
                                   sophistication to the dashboard event
                                   payload

config.py                         MODIFIED — add "Exfiltration" and
                                   "Session Hijacking" to SEVERITY_LEVELS
                                   and RESPONSE_MATRIX (Exfiltration's MITRE
                                   mapping already exists in
                                   MITRE_ATTACK_MAP; Session Hijacking gets
                                   no MITRE mapping, same precedent as CSRF
                                   -- doesn't fit the ATT&CK post-compromise
                                   scheme any more precisely than CSRF did)

lab/verify_exfil_detection.py     NEW — mirrors verify_dos_detection.py's
                                   structure

lab/verify_session_hijack.py      NEW — mirrors verify_beacon_detection.py's
                                   structure, using synthetic raw HTTP
                                   requests instead of Scapy packets (this
                                   check operates on payload text, not
                                   packet timing)
```

## Ransomware — deferred, not built

**Why it's not in this round:** the only credible network-visible ransomware
signal (a burst of rapid file-write operations across an SMB/file-share
protocol, port 445) requires an actual SMB/file-share service to generate
that traffic shape against. This lab's target (`lab/target_service.py`) is
an HTTP Flask app — there is no file-share traffic anywhere in this
environment to test a detector against, live or synthetically, without
first building a fake SMB target service (a materially bigger, separate
piece of infrastructure work).

Building a "detector" that can never be exercised against real or realistic
traffic in this lab would be indistinguishable from a hollow heuristic
picked to satisfy a checklist — exactly what CLAUDE.md's "never write toy
implementations" rule exists to prevent. The two secondary signals
(C2-domain/Tor-exit-node correlation, connection-frequency anomalies) are
already partially covered by the existing Bot/beacon detector and
`intelligence/ip_reputation.py`'s Tor-node checking — a dedicated
"Ransomware" label on top of those would just be relabeling existing
detections without adding new information.

**Real scope for a future session:** stand up a minimal SMB/file-share
target (or a fake SMB honeypot service, extending the existing
`intelligence/honeypot.py` pattern), then a burst-write-rate heuristic
against that traffic — mirroring tonight's Exfiltration/DoS threshold
pattern once there's something real to threshold against.

## Testing

Both new checks get a dedicated verify script, following this project's
established pattern (`lab/verify_beacon_detection.py`,
`lab/verify_dos_detection.py`): synthetic inputs constructed directly (no
live capture needed), asserting both the positive case (attack-shaped input
correctly flagged) and the negative case (a plausible false-positive shape
correctly NOT flagged), then `python sentinel.py health` to confirm pipeline
wiring stays clean (module count unchanged — no new module files, only
modifications to existing ones).
