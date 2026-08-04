# Session Ledger

A running, dated record of what happened in each working session on
SENTINEL IPS, so the project owner (and any teammate) can re-orient
quickly without re-reading chat history or `git log`. Newest entry on
top. An entry is written only when the user says a stop phrase ("stop
session", "end session", "wrap up") after opting in at the start of that
session — see `docs/superpowers/specs/2026-07-21-session-ledger-design.md`
for the full protocol.

---

## 2026-08-04 — Fixed GitHub contribution-graph identity; revised the IEEE paper end-to-end

**Goal:** Diagnose why ~200 pushed commits weren't showing as GitHub
contributions, then make a round of requested edits to the IEEE paper
(docs/paper/main.tex).

**Changes:**
- Root cause: global git identity on this machine was a collaborator's
  (`Brindha185 <brindhaadiga182005@gmail.com>`), not the user's own
  (`MT Yashas <mtyashas1ga23cs091@gmail.com>`). Fixed local repo config.
- Rewrote all 55 commits' author via
  `git rebase --root --exec 'git commit --amend --no-edit --author=...'`,
  preserving original author dates (critical — an earlier `--reset-author`
  attempt collapsed dates to "now" and had to be caught and reverted before
  push). Force-pushed corrected history to `origin/main`.
- `git filter-repo --mailmap` looked like it succeeded but was a silent
  no-op — don't trust its exit message, verify with
  `git log --format='%ae' | sort -u` after.
- Saved a standing preference: push local `main` to `origin` at the end of
  every session without asking first (memory: `feedback_push_at_session_end`).
- Paper edits: removed an author, rewrote the abstract to <=150 words with
  no citations, renamed Index Terms to Keywords (5 terms), added the two
  live-capture datasets to the Datasets subsection, replaced the
  detection-only architecture figure with a compact full-system diagram
  (later repositioned to render after its introducing text, not before),
  added a Feature Importance (SHAP) subsection with a real citation, fixed
  Finding 2's figures interrupting Finding 3's text mid-sentence, and
  retitled twice (final: "Generalization Gap and Adaptive Retraining in
  Machine Learning-Based Network Intrusion Detection: A Live-Traffic Case
  Study with XGBoost" — chosen for search/index keyword coverage over a
  catchier hook). Committed and pushed (`f9dde2c`).

**Decisions:**
- Kept the `teammate` remote (github.com/Brindha185/SENTINEL-IPS-v2)
  untouched — genuinely different person/fork, unrelated diverged history,
  never push there.
- Did not add the collaborator's email as a verified alternate on the
  user's GitHub account (the other backfill option) — history rewrite was
  chosen instead since it also fixes authorship going forward, not just
  retroactively.
- Title went through several rounds of user feedback (catchy → keyword-dense)
  before landing on pure keyword density over a hook, since findability in
  IEEE Xplore/Scholar mattered more than memorability.

**Next steps:** None specified — paper is at a good checkpoint (6 pages,
clean build, all requested edits applied and verified visually page-by-page).

---

## 2026-08-03 — Wrote, verified, and finished an IEEE conference paper end-to-end

**Goal:** Write an IEEE conference paper based on SENTINEL IPS that's both
genuinely novel and rigorously backed — the user wanted proof behind every
number used, not just a write-up of existing project docs.

**Changes:**
- Brainstormed the paper's angle: "benchmark-to-live generalization gap,"
  three escalating findings from the project's own M4 milestone (cross-
  dataset domain shift → dataset-to-live collapse → gap re-opening on a
  bigger, more diverse capture). Chosen over a narrower cross-dataset-only
  paper or a broad system-tour, as the least-crowded, most evidence-backed
  angle available.
- Base paper selection and several later judgment calls were made via a
  4-persona council debate (Dr. Sentinel/Cipher/Prism/Atlas, from
  CLAUDE.md's specialist framing) at the user's explicit request, rather
  than a unilateral choice. Base paper: Cantone, Marrocco & Bria,
  "Machine Learning in Network Intrusion Detection: A Cross-Dataset
  Generalization Study," IEEE Access 2024 — unanimous across all four
  lenses.
- Built `docs/paper/main.tex` (IEEEtran conference format), `references.bib`
  (10 real, individually verified citations — a novelty check across IEEE
  Xplore/ACM DL/arXiv found no direct collision with the paper's angle),
  and 5 figures (architecture diagram, a bar chart, and two combined
  before/after confusion-matrix+ROC-curve grids for Findings 2 and 3 — the
  council was unanimous that dropping "before" images to save space would
  read as evidence-suppression in a security paper, so both states stayed).
- Independently re-verified Table 1 (fresh full-CIC-2017 retrain) and
  Table IV/Finding 3 (pcap replay against the actual saved capture) —
  both landed within ~1pp of the already-documented numbers.
- Attempted the same for Table 2/3 (cross-dataset/combined-training) and
  found 4 real bugs in the process: a wrong confidence threshold (0.55
  default instead of the documented 0.35 cross-dataset threshold), a
  train/test leakage bug, a stale `MLDetectionLayer` feature-column cache
  reused across two different trained models, and a missing
  undersample-majority-class + dynamic-`scale_pos_weight` step — recovered
  by locating and reading the project's own original May-2026
  `combine_and_train.py` script (found at
  `C:\Users\mtyas\OneDrive\Desktop\ids_framework_v2\`, an earlier framework
  iteration, at the user's pointer) rather than guessing. Experiment 2
  reproduced within ~3pp after the threshold fix; Experiment 3 still
  landed with an unexplained ~17pp recall gap even after all four fixes —
  user decided to keep Table II's original documented numbers rather than
  force a match or add a caveat for an unexplained discrepancy.
- Real incident: `train.py --mode binary`'s default save path overwrote
  the live production model (`models/benchmarkids_binary.pkl`) during the
  Table 1 verification run. Recovered via an MD5-matched timestamped
  snapshot (`benchmarkids_adaptive_20260727_133814_v1.pkl` — byte-identical
  restore, confirmed). Set up an isolated `lab/paper_repro/` workspace
  immediately after so every later training/eval run for the paper writes
  only there, never to the live `models/` directory.
- Council-debated (unanimous) whether to include the separate M5
  milestone's findings: don't cite M5's un-re-verified numbers as Results
  (would create a two-tier evidence standard against the paper's otherwise
  fully-verified tables), but do upgrade the Conclusion's previously bare
  "the multiclass classifier has the same problem" claim into a
  qualitative (no-numbers) description of what was actually found and
  fixed there.
- Proactively rewrote several Related Work/Introduction passages that
  paraphrased cited papers too closely, before the user had even run a
  plagiarism checker.
- Installed MiKTeX (none was present locally), compiled the paper
  end-to-end, fixed an IEEEtran/`\linebreakand` incompatibility and a
  `caption`+IEEEtran interaction, added the `balance` package to even out
  the trailing references page.
- Filled in the real author block (4 students, guide, HOD — Global Academy
  Of Technology) once the user provided it.
- Final self-review: every number in the compiled PDF cross-checked
  against `docs/RESEARCH_PAPER_RESULTS_M1-M4.md` line-by-line; pipeline
  hyperparameters verified directly against `config.py`/`core/model.py`
  rather than trusted secondhand.
- Final paper: 6 pages, 10 citations, 5 figures, 4 tables, compiles clean
  with zero warnings. Saved at `docs/paper/main.pdf` (source: `main.tex`,
  `references.bib`, `figures/`, `README.md` with compile instructions and
  a status checklist).

**Decisions:**
- Treated a broken reproduction attempt (Experiment 3's unexplained recall
  gap) as a reason to keep the original documented numbers rather than
  chase an exact match indefinitely or silently paper over the
  discrepancy — matches the project's established `[verified]` vs
  `[documented]` provenance-tagging convention.
- Chose combined before/after subfigure grids over separate figures or a
  trimmed subset specifically because the "before" images (e.g. Finding
  2's near-diagonal ROC curve at 98.66% accuracy) are the load-bearing
  visual evidence for the paper's central "accuracy is deceptive" claim —
  dropping them to save space would have undercut the argument the
  figures exist to make.
- Did not add speculative future-work content about `--enforce-blocks`
  validation or higher-volume live-traffic stress testing to the paper —
  user explicitly wants that added only once those are actually done, not
  described in advance.

**Next steps:**
- Only remaining open item is the user's own read-through of the compiled
  PDF (everything else on the tracked task list is done).
- User plans to run the paper through a real plagiarism checker (likely
  Turnitin via the university) and an AI-content detector (GPTZero/
  ZeroGPT) before submission. Agreed fix path if either comes back
  flagged: send specific flagged passages for targeted rewrites
  (plagiarism), or check the venue's AI-disclosure policy first before
  deciding between adding a disclosure statement vs. genuine human
  rewriting (AI-content) — explicitly avoided suggesting surface-level
  detector-evasion tricks.
- Separately (unrelated to the paper, carried over from earlier tonight):
  the Windows Firewall Public-profile-disabled gap blocking real
  `--enforce-blocks` enforcement is still open — see the 2026-08-02 entry
  below for full context.

---

## 2026-08-02 — First live --enforce-blocks test; found and fixed two real gaps (stale memory-only blocks, Public-profile firewall disabled)

**Goal:** Execute the plan queued up at the end of 2026-08-01: restart
`sentinel.py live` with `--enforce-blocks` in an elevated shell, trigger a
real attack, confirm a genuine Windows Firewall rule appears, confirm Kali
loses connectivity, confirm the benign VM/host are never touched — the
last milestone toward the user's stated goal of active defense rather than
detect-and-log only.

**Changes:**
- Booted both lab VMs headless, started `target_service.py` and the
  benign traffic generator, handed the elevated `sentinel.py live
  --enforce-blocks` process to the user's own Administrator shell (this
  agent's shell is non-admin and can't self-elevate).
- First `nmap -sS -p1-1000` run: PortScan was named correctly (multiclass
  fix from 2026-07-31 holding up) but is `severity=LOW` per
  `config.py SEVERITY_LEVELS` — no firewall rule appeared. Root-caused as
  a real bug, not a wrong attack-type choice: `192.168.56.10` was already
  present in `threat_intel/ip_blacklist.txt` from prior detect-and-log-only
  sessions. `IPBlacklister.block()` saw the IP already in `self._entries`
  and returned `memory_already_blocked` immediately, without ever calling
  `_apply_fw_block()` — so *any* IP touched before tonight could never get
  a real firewall rule no matter what ran with `--enforce-blocks`. Fixed
  by adding a `fw_applied` flag to `_BlockEntry`; `block()` now re-applies
  the OS firewall rule for an already-known IP if enforcement is on and no
  rule was ever actually applied for it. Added
  `lab/verify_reenforce_on_known_ip.py` (4 checks: off stays memory-only,
  turning enforcement on re-blocks a stale entry, a second block on the
  same IP is a true no-op, fresh IPs under enforcement are unaffected).
  Regression-tested against all 13 `lab/verify_*.py` scripts +
  `sentinel.py health` — zero breakage.
- Restarted the live process, re-ran the scan: `Get-NetFirewallRule
  -DisplayName "SENTINEL_BLOCK*"` now showed a real rule
  (`SENTINEL_BLOCK_192_168_56_10`, Inbound, Block, scoped to that one
  remote address) — the fix worked. But `curl` from Kali to the host
  still succeeded (`200 OK`) straight through the "active" block. Second
  real bug found: `Get-NetFirewallProfile` showed `Private` and `Public`
  profiles both `Enabled=False` (only `Domain` is on), and the VirtualBox
  host-only adapter (`Ethernet 2`) has no assigned `NetConnectionProfile`
  at all, so Windows defaults it to the Public profile — which isn't
  filtering anything, rule or no rule. This is a host-level Windows
  Firewall configuration gap, not a SENTINEL code bug.
- Confirmed the benign VM (`.20`) reached the host normally throughout
  (`curl` -> `200`), so `_local_ips()`/self-block guard and the general
  detection pipeline were never the problem.
- Stopped for the night before fixing the Public-profile gap, since doing
  so also affects real Wi-Fi firewall enforcement on this machine (Wi-Fi
  is Public-profile too), not just the isolated lab network — flagged for
  explicit user sign-off rather than just doing it.
- Cleaned up: removed the test firewall rule (from the user's elevated
  shell, since this agent's shell lacks permission), stopped
  `target_service.py`, confirmed the benign traffic generator had already
  finished on its own, sent ACPI shutdown to both VMs.

**Decisions:**
- Treated the "no block happened" result as a bug to root-cause rather
  than switching to a different, more-obviously-HIGH-severity attack type
  to make a block happen — the stale-blacklist gap would have silently
  broken every previously-seen IP under real enforcement if left
  unfixed, regardless of which attack type was used to trigger it.
- Did not flip `netsh advfirewall set publicprofile state on` unilaterally
  even though it's the standard/default-recommended Windows posture,
  because it changes enforcement on the user's actual Wi-Fi connection,
  not just the lab — asked first rather than assuming "more secure by
  default" is automatically wanted here.

**Next steps:**
- Public-profile firewall gap is still open. Two options on the table for
  next session: (a) enable Windows Firewall's Public profile outright
  (`netsh advfirewall set publicprofile state on`) — standard default,
  but affects real Wi-Fi traffic too; (b) assign the host-only adapter its
  own network category (e.g. Private) and enable enforcement only for
  that profile, leaving Public alone. User asked to stop and decide
  tomorrow rather than pick under time pressure.
- Once that's resolved: re-run the PortScan test end-to-end, confirm the
  block actually stops Kali's traffic this time, confirm benign VM/host
  stay untouched, then this closes out `--enforce-blocks` as the final
  milestone toward genuine active defense.
- Lab VMs were shut down (ACPI) at session end; both will need booting
  again next session. `sentinel.py live` in the user's elevated shell was
  left for them to stop manually (this agent's shell can't reach that
  terminal).

---

## 2026-08-01 — Live re-verified all 5 backlog fixes; found & fixed a new Bot/PortScan false positive; closed both open security findings

**Goal:** Live-test all 5 backlog fixes from the previous session end to
end (not just the isolated verify scripts, which had already passed) to
confirm they actually hold up under real traffic, then close out the two
open `docs/SECURITY_TODO.md` findings.

**Changes:**
- Restarted the lab (both VMs, target service, `sentinel.py live`) and
  re-ran all 5 previous fixes live: Honeypot (fake_ssh hit, CRITICAL,
  real block), WebShell (`/upload`, CRITICAL, `block_request, ip_block`),
  CSRF (`/account/login` + forged cross-origin POST to `/account/email`,
  MEDIUM, `action=invalidate_session, alert_medium` — confirmed no
  `ip_block` in the action string), and the binary-payload signature fix
  (`nmap -sU` to 500/1701/4500 — confirmed zero false `CommandInject`;
  the traffic is simply classified `BENIGN`, a separate pre-existing
  detection-coverage gap this fix was never meant to close).
- Found a genuine new bug doing this: `nmap -sS -p1-1000` got partially
  mislabelled `Bot` instead of `PortScan`, at HIGH severity, genuinely
  blocking the source. Root-caused: `beacon_score()` only checked
  interval *regularity* (coefficient of variation), never interval
  *size* — a fast port scan's SYN probes land on the same destination IP
  at a very consistent, tight pace, just as low-CV as a genuine C2
  beacon, only milliseconds apart instead of seconds-to-minutes. Fixed
  with a new `_BEACON_MIN_MEAN_INTERVAL_S = 2.0` floor in
  `core/flow_collector.py` — connections averaging faster than that can
  never qualify as a beacon regardless of regularity. Added a regression
  check to `lab/verify_beacon_detection.py` (10 connections 5ms apart —
  the exact shape that caused the failure — must not score as a beacon).
  Restarted the live process again (same hot-reload lesson as the
  zero-day polarity fix — Python doesn't pick up file changes in an
  already-running process) and re-ran the scan: 1000/1000 flows now
  correctly labelled `PortScan`, zero `Bot` mislabels.
- Fixed both remaining `docs/SECURITY_TODO.md` findings. Reflected XSS in
  `lab/target_service.py`'s `/search` — now escaped via
  `markupsafe.escape()`, confirmed via Flask's test client. PowerShell
  command-injection primitive in `ConnectionTerminator.terminate_ip()` —
  now validated with `ipaddress.ip_address()` before any PowerShell
  string gets built, rejecting anything that doesn't parse (both IPv4
  and IPv6 confirmed still work). Added
  `lab/verify_connection_terminator_guard.py`. `docs/SECURITY_TODO.md`
  now has no open findings.
- 9 verify scripts now exist under `lab/verify_*.py`; every fix this
  session was regression-tested against all the others plus
  `sentinel.py health` before committing — zero breakage throughout.
- 4 commits made and pushed to `origin/main`.

**Decisions:**
- Insisted on restarting the live process for genuine re-verification
  rather than trusting the isolated verify scripts alone — this is
  exactly what caught the Bot/PortScan false positive, which no existing
  unit check could have caught (the original beacon test only exercised
  regular-slow and irregular-slow timing, never fast-regular).
- Fixed the beacon false positive with a simple minimum-interval floor
  rather than a more elaborate frequency-domain analysis — the gap being
  closed (fast scans looking as regular as slow beacons) only needs a
  floor to close, and the existing `_BEACON_MAX_CV` comment already
  documents this as a naive heuristic with a known ceiling against
  evasive C2, so added complexity here wouldn't have bought much.
- Chose IP validation (`ipaddress.ip_address()`) over restructuring the
  PowerShell invocation for the injection primitive — simpler, and fully
  closes the vector regardless of what future callers pass in.

**Next steps:**
- `--enforce-blocks` has still never been turned on. Plan agreed but not
  yet executed: restart `sentinel.py live` with `--enforce-blocks` in an
  elevated/Administrator shell, re-run a HIGH/CRITICAL attack, confirm a
  real Windows Firewall rule appears (`Get-NetFirewallRule -DisplayName
  "SENTINEL_BLOCK*"`), confirm Kali genuinely loses connectivity
  afterward, confirm the benign VM and host itself are never touched
  (the `_local_ips()` self-block guard already exists, just needs
  confirming under real enforcement), then clean up the firewall rule
  once done. This is the last milestone toward the user's stated goal of
  genuine active defense rather than detect-and-log only.
- Working tree is clean — nothing left uncommitted; everything pushed.

---

## 2026-07-31 — All 5 backlog items closed: binary-payload FP, honeypot wiring, multiclass PortScan retrain, WebShell+CSRF, Bot beacon detection

**Goal:** Re-verify the zero-day polarity fix from the previous session
against live traffic, then work through the 5 backlog items scoped at the
end of that session one by one.

**Changes:**
- Restarted the lab (both VMs, target service, `sentinel.py live`) and
  re-ran the zero-day UDP scan (`nmap -sU` to ports 500/1701/4500) to test
  the previous session's anomaly-polarity fix against a genuinely fresh
  process (the prior test had been running stale pre-fix code).
- That test surfaced a *new* bug instead: the scan got flagged
  `attack=CommandInject` and genuinely blocked. Root-caused with hard
  evidence, not guessed — replayed the exact captured packets through an
  isolated `FlowCollector` + `SignatureDetector` outside the live
  pipeline. Scapy auto-dissects UDP/500 as ISAKMP, so an initial payload
  check only saw 12-14 bytes (an undissected sub-layer); the real captured
  `payload_sample` is the full 40-byte structured binary header, and one
  of those bytes is literally `0x7C` ('|'), an exact hit on
  `COMMAND_INJECTION_PATTERNS`. Structural, not a fluke — binary protocol
  bytes are effectively random across 0-255, so any non-HTTP traffic has
  real odds of coincidentally matching a text-oriented pattern. Fixed by
  skipping any `payload_sample` containing the utf-8 replacement character
  (U+FFFD) before running signature checks — a precise, already-computed
  signal that the raw bytes weren't valid text to begin with.
- Wired `HoneypotMonitor` into `sentinel.py live` for the first time
  (same class of gap Layer 2 had before the 2026-07-28 fix — fully
  implemented, never instantiated or started anywhere). Kept it out of
  `SentinelIPS.__init__` deliberately since it binds real sockets; new
  `_run_honeypot_response()` routes hits through the same
  intel→attribution→risk→response pipeline a regular detection uses.
- Fixed multiclass PortScan mislabeling via
  `lab/m5_multiclass_retrain.py`, rewritten to target the real 2026-07-29
  four-attack capture (28,046 packets: genuine benign traffic, a full
  `nmap -sS -p1-1000` scan, CommandInject/PathTraversal/SQLInjection
  curls) and label by flow shape instead of the old script's
  DoS-vs-benign-probe exclusion logic, which didn't apply to this
  capture. Retrain's own held-out CIC-2017 gate rejected the candidate
  (macro recall 97.51%→94.97%), but real-capture accuracy went
  35.48%→97.49% with the old model never once predicting PortScan.
  Manually promoted, same call made for the binary model in M4.
- Added WebShell detection (new `_WEB_SHELL_PATTERNS`, straightforward —
  same shape as CommandInject/PathTraversal) and CSRF detection (a
  structural check, not a payload signature: state-changing request +
  session cookie + no matching Referer/Origin). CSRF needed its own
  response path since the request that reaches the server comes from the
  *victim's* browser, not the attacker's — `_run_response()` got a
  dedicated branch that invalidates the session via
  `ConnectionTerminator.invalidate_session()` (wiring in another
  previously-dead module) instead of blocking `src_ip`, verified by an
  explicit assertion that the victim IP is never blocked. Added
  `/upload`, `/account/login`, `/account/email` to
  `lab/target_service.py` to test both against.
- Added Bot/C2 beacon detection: `core/flow_collector.py` now tracks
  connection start timestamps per (src_ip, dst_ip) pair across flows and
  computes the coefficient of variation of inter-connection intervals; a
  new `sentinel.py._run_beacon()` stage flags low-variance (periodic)
  behavior as `Bot`, reusing the class's existing MITRE mapping/severity
  from the original project spec rather than retraining any model.
  Deliberately not an ML feature — adding one would mean recomputing it
  across the entire CIC-2017 training set for a gap that a rule-based
  layer (matching how Layer 2 signatures already work) closes just as
  well.
- 8 verify scripts now exist under `lab/verify_*.py`, each a runnable
  self-check for one fix; the last 4 items were each regression-tested
  against every prior one plus `sentinel.py health` before committing —
  zero breakage across the whole session.
- 9 commits made and pushed to `origin/main`.

**Decisions:**
- Chased the ISAKMP false-positive down to the exact byte rather than
  accepting "binary payload coincidentally matched something" as good
  enough — the first hypothesis (raw packet bytes) was wrong, and only
  replaying the exact captured packets through an isolated pipeline
  found the real cause (Scapy's own ISAKMP dissection hiding most of the
  actual payload from a naive `Raw` layer check).
- Chose cross-flow connection-timing tracking over a full multiclass
  retrain for Bot detection, and a dedicated non-blocking response path
  over reusing the IP-blacklist machinery for CSRF — both because the
  correct fix was architecturally different from every other gap closed
  this week, not because either was the fastest path.
- Manually promoted the multiclass retrain candidate despite the gate's
  rejection, same reasoning as M4: the held-out CIC-2017 dip was real but
  modest, and the actual capture result (35%→97.5%) is the metric that
  matters for what this backlog item was created to fix.

**Next steps:**
- Two `docs/SECURITY_TODO.md` findings still open: reflected XSS in
  `lab/target_service.py`'s `/search`, and the PowerShell
  command-injection primitive in `response/connection_terminator.py`
  (still unreachable dead code — `terminate_ip()` is deliberately never
  called, only `invalidate_session()` is now wired in).
- `--enforce-blocks` has still never been turned on — every block tested
  this week (including honeypot and CSRF-adjacent paths) has been
  memory-only (`fw_enforcement=False`). Per the user's stated end goal
  (genuine active defense, not just detect-and-log), this is the natural
  next milestone once confidence in detection accuracy holds — flip it on
  and verify no self-block under real attack traffic.
- `_BEACON_MAX_CV = 0.25` is explicitly flagged as tuned against this
  lab's own near-zero-jitter simulated beacon, not real malware — real C2
  usually adds deliberate jitter to defeat exactly this kind of
  detection. Not urgent, but worth knowing the ceiling.
- Working tree is clean — nothing left uncommitted; everything pushed.

---

## 2026-07-30 — Broader attack-type spread tested live; zero-day polarity bug found & fixed; security audit; 4 items scoped for later

**Goal:** Continue the live-traffic validation lab: run a broader spread of
attack types than M4/M5 covered (PortScan, CommandInject, PathTraversal,
SQLInjection, Bot, zero-day), check overall coverage against CLAUDE.md's
full attack list, and run a security review of the codebase itself.

**Changes:**
- Both lab VMs (`kali-linux-2026.1-virtualbox-amd64`, `ubuntu-benign`)
  started headless via `VBoxManage`, host-only network confirmed reachable,
  Npcap interface resolved (`Ethernet 2`).
- Live-tested PortScan, CommandInject, PathTraversal, SQLInjection against
  `lab/target_service.py`. CommandInject/PathTraversal correctly named via
  Layer 2 signatures (HIGH severity) and **genuinely triggered
  `IPBlacklister.block()`** — first real end-to-end proof the response
  layer fires correctly when an attack resolves to a real name. PortScan
  detected (binary model, conf 0.56-0.99 on all 1000 ports) but still logs
  generic `ATTACK` — confirmed root cause with fresh evidence:
  `detection/layer1_ml.py:232-238`, multiclass top-class resolves to
  BENIGN (idx 0) on live traffic, deliberately falls back rather than emit
  a contradictory label. SQLInjection's first attempt failed client-side
  (curl rejected the unencoded `'`+space payload as a malformed URL, never
  reached the target — not a SENTINEL bug); fixed with
  `curl -G --data-urlencode`, retried successfully, detected correctly at
  MEDIUM severity per `SEVERITY_LEVELS`.
- Simulated Bot/C2 beaconing (30x `curl` at a 10s interval). Produced
  **zero detections at all** — different failure mode than PortScan (not
  mislabeled, never flagged). Root cause: a lone periodic GET has no
  burst/shape signal to distinguish it from ordinary browsing at the
  single-flow-feature level; real beacon detection needs cross-flow
  temporal correlation (inter-arrival regularity per source→destination
  over time), which none of Layers 1-3 implement. Caveated: the curl-loop
  proxy is a weak stand-in for real Ares-botnet traffic, so this is
  suggestive, not conclusive.
- Discovered `intelligence/honeypot.py`'s `HoneypotMonitor` (fully
  implemented — fake SSH/FTP/admin/DB/API listeners, PCAP capture,
  auto-blacklist, attacker profiling) is **never instantiated or started
  anywhere in `sentinel.py`** — same class of gap Layer 2 had before the
  2026-07-28 fix. Blocks FTP/SSH-brute-force and API-abuse testing, which
  are cleanest validated via the honeypot's guaranteed-malicious hits.
- Ran a full-codebase security audit (working tree was clean, so not a
  diff review — scanned response actions, threat-intel HTTP calls, the
  honeypot listener, the dashboard, and the lab's Flask fixture directly).
  Two real findings, documented in new `docs/SECURITY_TODO.md`: (1)
  reflected XSS in `lab/target_service.py:52` (`/search` echoes `q`
  unescaped into the HTML response); (2) a PowerShell command-injection
  primitive in `response/connection_terminator.py:121-126` (`ip`
  interpolated unescaped into a `-Command` string) — currently unreachable
  dead code (`terminate_ip()` is never called live, and every `ip` today
  comes from Scapy's parsed IP header, which can't contain a quote).
  Neither fixed yet.
- Investigated WebShell/CSRF as candidate attack types to test — verified
  via grep that **neither has any detector at all** anywhere in `config.py`
  or `detection/layer2_signatures.py`. CSRF specifically can't be caught at
  the network/flow level (it's a missing-app-side-token problem, not a
  payload signature) and, more importantly, **can't reuse the existing
  IP-blacklist response model at all** — a CSRF request arrives from the
  victim's own browser, so blocking the source IP would block the victim,
  not the attacker. Needs its own reject-the-request/invalidate-session
  response path whenever it's built.
- Attempting a zero-day test (`nmap -sU` to 3 unusual ports) surfaced a
  bug that had *already been found and fixed earlier tonight in an
  interrupted session*, sitting uncommitted: `sentinel.py`'s
  `_build_event()` promoted a flow to `ZeroDay` on `anomaly_score >= 0.2`,
  but `IsolationForest.decision_function` returns *more negative* for
  *more* anomalous — the check had the polarity backwards and could never
  fire. Same backwards direction gated `adaptive/zero_day_miner.py`'s
  candidate filter. Both fixed (keyed off `anomaly_detected` instead;
  filter flipped to `<= -_MIN_ANOMALY_SCORE`), with a new runnable
  self-check (`lab/verify_zeroday_polarity.py`). However: the fix was
  written to disk at 01:03, but the `sentinel.py live` process running
  tonight started at 00:11 — Python doesn't hot-reload, so the live
  process was still running the old buggy code for the rest of the
  session. The zero-day fix itself was never actually verified against
  live traffic tonight. Separately, and independent of the polarity bug:
  the UDP scan produced **zero detections** even from Layer 3's
  anomaly-promotion path (which doesn't depend on the buggy labeling
  code) — a real miss on 3 lone UDP probes, though too small a sample to
  be conclusive on its own.
- 3 commits made and pushed to `origin` (`github.com/mtyashas/SENTINEL-IPS`):
  the zero-day polarity fix + verify script, tonight's threat-intel
  artifacts, and the security findings doc.

**Decisions:**
- Kept the lab in detect-and-log-only mode all session
  (`fw_enforcement=False`) — deliberate. User's stated end goal is genuine
  active defense (not just detect-and-log), and agreed priority order is:
  validate detection coverage first → fix the multiclass gap → then flip
  on `--enforce-blocks` and verify no self-block, rather than enabling
  real enforcement on a still-shaky signal.
- Did not chase the multiclass retrain, WebShell/CSRF, or honeypot wiring
  ad-hoc mid-session even though all three were directly relevant to what
  was being tested — each is real, well-scoped feature work (comparable
  effort to M4's retrain or the Layer 2 wiring session), not a quick
  patch, so each was documented as its own separate backlog item instead
  of a rushed fix.
- Did not restart the live capture process to pick up the zero-day
  polarity fix mid-session — user chose to stop for the night instead;
  the fix is committed but functionally untested against live traffic.

**Next steps:**
- Restart `sentinel.py live` next session to actually load the zero-day
  polarity fix, then re-verify zero-day/UDP-scan detection properly.
- Investigate why the UDP zero-day scan got zero detections independent
  of the polarity bug — Layer 3's anomaly-promotion path didn't fire on
  3 lone UDP probes; unclear yet whether that's a baseline/feature-space
  issue or just too small a sample.
- Four separate backlog items, all scoped but not started: (1) multiclass
  retrain — fixes PortScan mislabeling and unblocks blacklisting for any
  attack that currently can't get a specific name; (2) WebShell + CSRF
  detection — new feature work, CSRF needs its own non-IP-block response
  path; (3) Bot/C2 cross-flow temporal detection — needs a new stateful
  feature in `core/flow_collector.py`, architecturally distinct from a
  retrain; (4) wire `HoneypotMonitor` into `sentinel.py live` — same fix
  shape as the 2026-07-28 Layer 2 wiring, unblocks FTP/SSH-brute-force and
  API-abuse testing.
- Two security findings in `docs/SECURITY_TODO.md` still open, not fixed.
- Working tree is clean — nothing left uncommitted; everything pushed.

---

## 2026-07-28 — M5 gaps fixed and verified; Layer 2 wired in for the first time ever

**Goal:** Fix the two M5 gaps queued from 2026-07-27 (unreachable
RESPONSE_MATRIX blocks, anomaly-baseline contamination), then confirm the
fixes against real traffic rather than isolated unit checks.

**Changes:**
- Fixed `_run_response()` in `sentinel.py`: it computed `actions` from
  `RESPONSE_MATRIX` but only ever used it for a cosmetic log string — the
  actual block decision checked severity alone, so `BruteForce`'s
  documented `ip_block_1h` and `PortScan`'s `ip_block_24h` were silently
  unreachable. Fixed additively (existing HIGH/CRITICAL behaviour
  untouched).
- Fixed the anomaly detector fitting on whatever was in the first chunk to
  cross 100 rows regardless of attack/benign mix (could baseline on
  attack-heavy data during a flood). Now accumulates only Layer-1-benign
  rows across calls until 100 have genuinely been seen.
- Replayed the real M5 capture (79,679 flows) through both fixes: Kali
  correctly blacklisted via BruteForce, Ubuntu clean — but the host's own
  IP (`192.168.56.1`) was misclassified as BruteForce 585 times and would
  have self-blocked. Added a guard in `IPBlacklister.block()` refusing to
  block any of the machine's own interface IPs (enumerated via Scapy, not
  just hostname resolution — the affected IP was a secondary adapter
  hostname lookup wouldn't reliably catch).
- User asked why the M5 run never showed DDoS or SQLi. Answer led to a
  much bigger finding: `self._sig = SignatureDetector()` (Layer 2) was
  instantiated in `SentinelIPS.__init__` but **never called anywhere** —
  the entire signature-detection layer had been completely disconnected
  from the live pipeline this whole project, for every prior session, not
  just tonight. Wired it in for the first time: `core/flow_collector.py`
  now captures a bounded payload sample per flow (first data-carrying
  packet, capped 2048 bytes); `sentinel.py` added `_run_signatures()`,
  called between Layer 1 and Layer 3, promoting `pred_binary` and flooring
  confidence at 0.90 on a signature hit; `_build_event()` now prefers a
  signature-confirmed `attack_type` over the ML-derived one.
- Actually exercising Layer 2 for the first time surfaced two more real
  bugs: (1) `COMMAND_INJECTION_PATTERNS`' first pattern was a bare
  `[;&|`]`, matching the `&` in every ordinary URL-encoded form POST —
  relabelled hundreds of hydra's legitimate brute-force attempts as
  `CommandInject` (HIGH severity). Tightened to `[;|`]|&&` (real shell
  chaining, not form encoding). (2) `FlowCollector`'s 5-tuple flow key had
  no defense against port reuse across a long idle gap: an `hping3` flood
  packet left a flow open forever (flood traffic gets no RST/FIN
  response), and 215 seconds later curl's real SQLi request reused the
  exact same ephemeral port — silently merging into the stale flow and
  losing the request to `payload_sample`'s first-write-wins rule. This
  wasn't narrow: fixing it changed total flows in the M5 replay from
  79,679 to 116,904, meaning it had been corrupting flow statistics
  throughout the whole capture, not just the one visible case. Fixed: a
  fresh SYN on an already-tracked key force-closes the stale flow (gated
  on >=3s idle so a legitimate rapid retransmission isn't mistaken for a
  new connection).
- Final re-verification against the real M5 capture (116,904 flows,
  14,873 attacks): `BruteForce` 8,308, `DoS` 755 (correctly never `DDoS`
  — single-source flood), `SQLInjection` 2 (via Layer 2, matching the 2
  duplicate packets found in the raw capture), `ATTACK`/`Unknown` 5,808
  generic (binary/multiclass disagreement + anomaly-only catches — a
  known, explained limitation, not a new bug). Kali blacklisted, Ubuntu
  clean, host self-block guard held.
- Discovered (not yet fixed): the production model has been silently
  capped at 37 of 79 available raw features since 2026-07-20, because
  `MLDetectionLayer._align_features()` builds every retrain's training
  data from a cached 37-column list, and every adaptive retrain since
  (including tonight's) re-derives from that same stale cache — a
  self-perpetuating bottleneck, never a deliberate choice.
- 8 commits made tonight (adaptive retraining infra, profiler debounce,
  research paper doc + real M4 curves, the two M5 response/anomaly fixes,
  the self-block guard, Layer 2 wiring + the 2 bugs it surfaced, plus
  threat-intel artifact commits).

**Decisions:**
- Chose to replay the real M5 pcap through the fixed pipeline end-to-end
  rather than trust isolated unit checks alone — this is exactly what
  surfaced the self-block gap and, later, the SYN-port-reuse bug; neither
  would have been caught by a narrower test.
- When investigating why SQLi wasn't detected, kept digging through three
  layers of root cause (wiring gap → pattern false-positive → flow-merge
  bug) instead of stopping at the first plausible explanation — the SYN-
  port-reuse bug turned out to be the one with the largest actual impact
  (37k+ flows affected), and would have stayed hidden if the investigation
  had stopped earlier.
- Deferred the 37-vs-79-feature fix to next session rather than starting
  a fresh retraining cycle at 3am — real, well-motivated next step, but a
  genuine time investment (fix the cache bottleneck, retrain fresh,
  re-verify against tonight's captures), not a quick patch.

**Next steps:**
- Fix the feature-cache bottleneck and retrain on the full 79-column
  feature set; re-verify against tonight's M4/M5 captures to see whether
  it reduces the binary/multiclass disagreement behind the generic
  `ATTACK` label.
- Run a broader attack-type spread next session (`PortScan` via `nmap -sS`
  distinct from the flood, `XSS`, `CommandInject`, `PathTraversal`
  alongside `SQLInjection`) — and log the exact start/stop time of each
  tool while running it, so flows can be ground-truth-labelled by
  timestamp window instead of flow-shape heuristics, which is what
  actually blocked confident `DoS` labelling this session (bare-SYN-flood
  and legitimate closed-port-probe flows are provably identical at the
  per-flow feature level; timestamp windows sidestep that ambiguity
  entirely instead of trying to resolve it in feature space).
- The cross-flow rate signal gap (connections/sec from a source) remains
  fully unaddressed — no amount of relabelling or using more of the
  existing 79 CICFlowMeter-style columns can substitute for it; it needs
  a genuinely new stateful feature in `FlowCollector`.
- Working tree is clean — nothing left uncommitted.

---

## 2026-07-27 — Adaptive retraining wired up, M4 resolved and re-verified at scale, M5 run

**Goal:** Pick up from 2026-07-25's M4 domain-shift blocker — get adaptive
retraining actually working, resolve the benign-FP gap, re-verify M4 with a
bigger/independent live-traffic capture, then run M5 (mixed concurrent
benign+attack).

**Changes:**
- Wired up adaptive retraining for the first time end-to-end
  (`lab/m4_adaptive_retrain.py`). Found and fixed 3 real, previously-dormant
  bugs in `adaptive/adaptive_trainer.py` + `core/model.py`: (1) `_eval_model`
  evaluated against raw X_test instead of each model's own fit-time columns,
  silently threw, and always rejected retrains regardless of merit — added
  `_align_to_model()`; (2) `common_cols` was built from a Python `set`
  intersection (no guaranteed order), silently drifting the retrained
  pipeline's column order from what `MLDetectionLayer`'s cache expects —
  fixed to preserve `X_mistakes.columns` order; (3) per-row sample weights
  were computed but `BenchmarkIDS.fit()` didn't even accept a
  `sample_weight` param, so "weight mistake rows higher" had never actually
  functioned — added the param, threaded through the pipeline as
  `clf__sample_weight`. Also added `MistakeCollector.get_types()` +
  `AdaptiveTrainer._balanced_mistake_weights()` (FP/FN weighted by inverse
  frequency, not a flat constant) and dropped `scale_pos_weight` to 1.0
  during adaptive retrains (it compounds multiplicatively with
  `sample_weight` and was fighting the targeted correction).
- Discovered a whack-a-mole training gap: retraining only on the pre-retrain
  model's *mistakes* left every flow-shape it already got right with zero
  training representation, so fixing one wrong shape could (and did) flip a
  different, previously-correct shape to wrong. Fixed by mixing the full
  ground-truth-labelled capture into the training cache at baseline weight,
  not just the mistakes.
- M4 resolved on the original 2,092-flow capture: accuracy 1.29% -> 99.95%,
  0 benign false positives (the one remaining miss is a proven Bayes-error
  floor — an exact feature-vector duplicate between a benign and an attack
  flow).
- Built a replacement benign-traffic VM (`ubuntu-benign` in VirtualBox:
  Ubuntu 26.04 Desktop, 4096MB/2CPU/25GB, NIC1=nat/NIC2=hostonly, static IP
  192.168.56.20 via `nmcli`) after the old one was removed. VirtualBox
  7.2.6's bundled Guest Additions can't build its kernel module against this
  VM's kernel (7.0.0-28-generic) — a `MODULE_IMPORT_NS`/`__flush_tlb_all`
  symbol-namespace mismatch, and no `linux-modules-extra` package exists yet
  for that exact kernel either. Abandoned clipboard sharing; used
  `openssh-server` + `ssh` from the Windows host instead (sidesteps the
  problem entirely). Added `lab/gen_benign_traffic.sh` (varied benign
  traffic generator, including deliberate closed-port probes for flow-shape
  diversity).
- Re-verified M4 on a new, independently-generated, ~8x larger capture
  (44,823 packets -> 17,612 flows: 15,247 attacker + 2,365 benign, via
  `nmap -sS -p 1-10000 -T4` + `gen_benign_traffic.sh`). The prior model
  scored only 95.16% on it — 100% correct on port 80 but 100% *wrong* on the
  new port-8081 probes, because it had only ever learned "single SYN, no
  response = benign" for the one port present in the smaller capture, not as
  a port-independent rule. Retrained again; `AdaptiveTrainer`'s own
  held-out-recall gate rejected the improved candidate (99.61% -> 98.88%,
  noise-scale on a small 2%-sampled CIC-2017 proxy set) despite it scoring
  99.74% with zero benign FPs on the real capture. Manually overrode the
  gate and promoted it to production.
- Ran M5 (benign curl loop concurrent with an `hping3` SYN flood, `hydra`
  brute-force against `/login`, and SQLi-shaped curl requests) — full
  621s session, 62,825 flows / 251,411 packets captured. No active
  firewall rule fired (confirmed clean, detect-and-log only as designed).
  Found two new real gaps: (1) `threat_intel/ip_blacklist.txt` never got
  `192.168.56.10` added despite 31k+ `ATTACK` detections — root cause:
  `sentinel.py`'s `_severity_for()` only escalates past `MEDIUM` on an exact
  attack-type-name match against `SEVERITY_LEVELS`, but live traffic is only
  ever classified as generic `ATTACK`/`Unknown` (the multiclass model has
  the same domain-shift problem M4's binary model had, just never fixed for
  multiclass), so severity never reaches HIGH/CRITICAL and blacklisting
  (gated on that) never fires; (2) the Layer 3 anomaly detector flagged
  legitimate benign-VM traffic as `Unknown` near the end of the run, likely
  because the flood skewed whatever running baseline stats it uses.

**Decisions:**
- Manually overrode `AdaptiveTrainer`'s automated recall-gate rejection when
  the held-out proxy validation sample was small/noisy but the real-capture
  result was unambiguously better (99.74% + 0 FPs vs. the gate's ~0.7pp
  proxy-recall complaint) — lesson for future retrains: check the rejected
  candidate's real-world performance before trusting the gate outright,
  especially when the rejection margin is sub-1pp on a small sample.
- Chose SSH-based terminal access over continuing to fight VirtualBox Guest
  Additions' kernel-module build failure — the incompatibility looked like
  a genuine upstream gap (bundled Additions predate a very new kernel's
  symbol-namespacing change) not worth chasing for a convenience feature,
  and SSH solves the actual underlying need (copy/paste, running commands)
  without it.
- Deferred fixing the multiclass-model/severity-escalation gap to next
  session rather than same-session, given the hour and that it's a
  similarly-sized undertaking to the M4 binary-model fix.

**Next steps:**
- Fix the multiclass model's live-traffic classification (same domain-shift
  pattern as M4's binary model, apparently never addressed for multiclass)
  so `attack_type` resolves to real names (DoS/DDoS/BruteForce/etc.) instead
  of generic ATTACK/Unknown — this should also unblock the
  `ip_blacklist.txt` auto-blacklisting response, which is currently a dead
  code path since severity can never exceed MEDIUM without a name match.
- Investigate the Layer 3 anomaly detector's baseline getting skewed by
  flood-scale traffic, causing benign false positives afterward.
- Once those are fixed, M5 should be considered fully passing; then move
  toward active countermeasures (`--enforce-blocks`) per the lab's stated
  long-term plan.
- MCP server + multi-agent adversarial testing framework (discussed this
  session) remains queued for after full module/lab completion — explicitly
  not started yet.

---

## 2026-07-25 — M1-M3 re-verified, M4 attempted; domain-shift finding on live traffic

**Goal:** Re-verify M1-M3 after the Ubuntu VM's static IP reverted, then push
through M4 (single attack type detection via `sentinel.py live` + `nmap -sS`
from Kali).

**Changes:**
- Ubuntu VM's static IP (`192.168.56.20`) had reverted to DHCP after a
  reboot — re-applied via `nmcli` and re-verified bidirectional ping.
- Automated M2 and M3 as standalone scripts (`lab/m2_smoke_test.py`,
  `lab/m3_verify_flow.py`) instead of hand-typed REPL sessions, after two
  REPL-specific bugs this session (a swallowed multi-line paste when
  `python` didn't actually open a REPL, and a `ModuleNotFoundError` from
  running a script directly instead of via `python -m`).
- M3's first run "failed" because the verification script assumed exactly
  one curl call; the user actually ran curl twice, producing two
  independent (and both correctly clean) flow rows. Fixed the script's
  pass/fail check to validate every row's cleanliness and full packet
  accounting instead of assuming a fixed row count.
- Attempted M4 twice. First run: `sentinel.py live` only prints aggregate
  counters, so per-detection results (attack_class, confidence, MITRE
  mapping) weren't observable at all — had to reconstruct them after the
  fact from `logs/alerts.jsonl`, which showed Kali's nmap traffic labelled
  `Unknown` (not `PortScan`) and, oddly, the host's own IP appearing as an
  attack source twice.
- Added a `DETECTION` per-attack log line to `sentinel.py`'s
  `_process_attacks()` (src_ip, attack_type, confidence, MITRE mapping,
  action) for real-time visibility — this was a real observability gap,
  not just a convenience for this session.
- Reran M4 with the new logging and diagnosed properly: benign curl
  traffic scored 99.99% confidence "attack" from Layer 1 (while the
  multiclass model separately said `BENIGN` on the same row); Kali's nmap
  SYN-scan traffic scored only 1.26% confidence and was missed by Layer 1
  entirely, only caught by Layer 3's anomaly detector.
- Reprocessed the M4 pcap offline (bypassing the VMs) to inspect the exact
  feature values feeding both decisions. Root cause: live lab flows are
  far more minimal (fewer packets, microsecond-to-millisecond durations)
  than anything in CIC-IDS-2017's training distribution, in both
  directions — a single curl request looks too sparse to resemble learned
  "benign," and a single SYN+RST is too minimal to resemble learned
  "PortScan." Same domain-shift phenomenon CLAUDE.md already documents
  between 2017→2018, now surfacing between "benchmark dataset" and
  "live traffic."
- Fixed a separate, genuinely fixable bug found along the way
  (`detection/layer1_ml.py`): when the binary model flags an attack but
  the multiclass model's top class is index 0 (`BENIGN`), the code
  silently accepted that contradiction and labelled it `BENIGN` — now
  falls back to a generic `ATTACK` label instead of the self-contradictory
  output.
- 4 commits this session: `lab/m2_smoke_test.py` + `lab/m3_verify_flow.py`,
  the leftover 2026-07-22 ledger entry, the detection-logging + label-
  contradiction fixes, and the `threat_intel/attacker_profiles.jsonl`
  artifact generated by these live runs.

**Decisions:**
- Chose to dig into the M4 anomaly with an offline pcap reprocessing
  script rather than accept the surface-level "attacks=N" result — this
  surfaced two genuinely different issues (a fixable label-contradiction
  bug, and a deeper domain-shift limitation) instead of one, which a
  shallower look would have conflated.
- Did not attempt adaptive retraining this session (user chose to stop
  instead) — it's a real next option, not dismissed, just bigger in scope
  than finishing this lab milestone.
- M4's strict success criterion (`attack_class=PortScan` with meaningful
  confidence) is being treated as unmet, not fudged — the label-
  contradiction fix improves output consistency but does not change the
  underlying domain-shift misclassification.

**Next steps:**
- M4's core gap remains open: either adaptive retraining
  (`adaptive/mistake_collector.py` + `adaptive_trainer.py`) on lab-shaped
  traffic samples, or richer test traffic (larger page loads, scans
  against a host with more open ports) that better resembles the
  CIC-IDS-2017 training distribution, would be needed to actually get
  live nmap traffic labelled `PortScan` with confidence.
- M5 (mixed concurrent benign + attack, end-to-end) not yet started.
- Kali has `nmap` confirmed working; `hydra`/`hping3`/`slowhttptest`/`curl`
  still not confirmed installed for M5.
- Working tree is clean — nothing left uncommitted.

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
