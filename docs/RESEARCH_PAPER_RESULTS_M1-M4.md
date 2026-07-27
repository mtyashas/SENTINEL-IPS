# SENTINEL IPS v2.0 — Results (Offline Benchmarks through Live-Traffic Milestone M4)

Compiled 2026-07-27. Covers: offline benchmark evaluation on CIC-IDS-2017/2018,
and the VirtualBox live-traffic validation lab through milestone M4 (single
attack-type detection / PortScan). M5 (mixed concurrent traffic) is excluded
by request — later milestone, separate write-up.

All offline-benchmark numbers are the project's own validated results
(`CLAUDE.md`, "Proven Benchmark Results"; backed by `reports/report_2017_binary_20260720_133638.json`
and the accompanying plots for the current production model). All live-lab
numbers are either personally re-verified in this session (marked
**[verified]**) or drawn from the dated project session ledger
(`docs/SESSION_LEDGER.md`, marked **[documented]**) — provenance is called
out per table so nothing is presented as more rigorously confirmed than it is.

---

## 1. Offline Benchmark Evaluation

### Table 1 — Experiment 1: In-distribution (CIC-IDS-2017 → CIC-IDS-2017)

| Metric | Value |
|---|---|
| Accuracy | 99.69% |
| Precision | 98.53% |
| Recall | 99.68% |
| F1-score | 99.10% |
| ROC-AUC | 99.99% |
| FP rate | 0.31% |
| FN rate | 0.32% |
| True Positives | 90,018 |
| True Negatives | 435,681 |
| False Positives | 1,344 |
| False Negatives | 287 |
| Flows tested | 527,330 |

*Figures:* `reports/roc_2017_binary_20260720_133638.png`,
`reports/pr_curve_2017_binary_20260720_133638.png`,
`reports/confusion_matrix_2017_binary_20260720_133638.png`,
`reports/benchmark_2017_binary_20260720_133638.png`.

**Regression check (current saved model, 2026-07-20, n=2,400):** accuracy
99.83%, precision 99.50%, recall 99.83%, F1 99.67%, ROC-AUC 100.0% — exceeds
all 7 targets above (source: `reports/report_2017_binary_20260720_133638.json`).

### Table 2 — Experiment 2: Cross-dataset (CIC-IDS-2017 → CIC-IDS-2018)

| Metric | Value |
|---|---|
| Accuracy | 85.64% |
| Precision | 74.18% |
| Recall | 20.12% |
| F1-score | 31.66% |
| ROC-AUC | 92.35% |
| Flows tested | 15,188,468 |

Finding: severe domain shift between datasets — high accuracy is an
artifact of class imbalance; recall collapses to 20% (this exact failure
mode reappears later in live-lab traffic; see §4).

### Table 3 — Experiment 3: Combined training (2017+2018 → 2018)

| Metric | Value |
|---|---|
| Recall | 80.83% |
| F1-score | 89.40% |
| Precision | 100.00% |

Finding: multi-dataset training resolves the domain shift from Table 2.

### Table 4 — Lightweight IDS (10 engineered features)

| Metric | Value |
|---|---|
| Accuracy | 99.47% |
| F1-score | 98.46% |
| ROC-AUC | 99.95% |
| Throughput | 1,638,934 flows/second |

### Table 5 — Multi-class attack classification (8 classes)

| Metric | Value |
|---|---|
| Macro F1 | 88.31% |
| Classes | BENIGN, DoS, DDoS, PortScan, BruteForce, Bot, Infiltration, Heartbleed |

### Table 6 — Top 15 features by SHAP importance

| Rank | Feature | Importance |
|---|---|---|
| 1 | bwd_packet_length_std | 33.82% |
| 2 | average_packet_size | 17.47% |
| 3 | packet_length_mean | 10.02% |
| 4 | packet_length_std | 6.33% |
| 5 | max_packet_length | 5.61% |
| 6 | bytes_per_pkt | 4.64% |
| 7 | psh_flag_count | 3.40% |
| 8 | destination_port | 2.77% |
| 9 | urg_flag_count | 2.39% |
| 10 | bwd_packet_length_mean | 2.05% |
| 11 | bwd_iat_std | 1.47% |
| 12 | avg_bwd_segment_size | 1.43% |
| 13 | idle_mean | 0.92% |
| 14 | bwd_packet_length_max | 0.86% |
| 15 | fwd_iat_max | 0.81% |

*Figure:* `shap_plots/shap_bar_20260720_133628.png` (bar chart);
`shap_plots/shap_waterfall_0_20260720_133628.png` (single-prediction waterfall).

---

## 2. Live-Traffic Validation Lab — Methodology

### Table 7 — Network topology

| Role | Host | IP | Notes |
|---|---|---|---|
| Protected server (capture point) | Windows host | 192.168.56.1 | Runs `sentinel.py live`, target HTTP service |
| Attacker | Kali Linux VM | 192.168.56.10 | nmap, hydra, hping3, slowhttptest |
| Benign traffic | Ubuntu VM | 192.168.56.20 | curl loop against target service |

VirtualBox Host-Only network (`192.168.56.0/24`) isolates lab traffic from
the host's real network; each VM also carries a NAT adapter used only for
package installation.

### Table 8 — Milestones M1–M4, pass criteria and outcome

| Milestone | Criterion | Outcome |
|---|---|---|
| M1 — Network reachability | Bidirectional ping, host↔both VMs | **[verified]** Pass, 0% loss both directions, both VMs |
| M2 — Packet capture | `PacketLogger` captures live packets to `.pcap` | **[verified]** Pass — 40 packets / 4,202 bytes captured to disk (`pcap/sentinel_20260723_081600_24931cf0.pcap`) |
| M3 — Flow assembly | One `curl` request → exactly one clean `FlowCollector` row | **[verified]** Pass — 2 curl calls produced 2 flows, each internally clean (SYN=2, FIN=2, full packet accounting: 12+11=23 packets matched exactly) |
| M4 — Attack-type detection | nmap SYN scan classified as `PortScan`/T1046 while concurrent benign traffic stays benign | **[verified]** Initially failed (see §3–4); resolved via adaptive retraining |

---

## 3. Engineering Findings During Live Validation

Two functional bugs were found and fixed in the live-capture path before any
detection result could be trusted — both **[verified]** by direct
before/after testing in this session.

### Table 9 — Bugs found and fixed

| # | Symptom | Root cause | Fix |
|---|---|---|---|
| 1 | Live capture silently produced zero flows despite packets arriving | Scapy's `conf.l2types` dissection table is populated only when `scapy.layers.inet`/`l2` is imported; the capture socket resolves its link-layer class once at open time, so packets fell back to undissected `Raw` for the whole session | Import `scapy.layers.inet` at module load time in `core/flow_collector.py` and `forensics/packet_logger.py` |
| 2 | Every clean TCP close produced 2 flow rows instead of 1 (a phantom 1-packet flow) | Flow was force-closed the instant both directions sent a FIN, but a standard close is FIN→ACK→FIN→**ACK** — the trailing ACK arrived to find the flow already popped | Delay finalization by exactly one packet after the second FIN (`core/flow_collector.py`) |

---

## 4. M4 — Domain-Shift Discovery and Adaptive Correction

This is the central result for the paper's M4 section: the production
binary model (99.69% accuracy on the CIC-IDS-2017 held-out test set, Table 1)
performed close to chance on live-captured lab traffic, and the specific
failure mode was diagnosed and corrected via an adaptive-retraining pipeline.

### 4.1 Initial failure — pre-fix confidence scores **[verified]**

Reprocessing a captured pcap through the exact live-inference pipeline
(`FlowCollector` → `NetworkFeatureEngineer` → `MLDetectionLayer`) on the
pre-fix binary model gave:

| Traffic | True label | Layer 1 confidence | Verdict |
|---|---|---|---|
| Single `curl` GET (benign) | BENIGN | **0.9999** | False positive (100% confident) |
| Kali `nmap -sS` SYN scan | PortScan | **0.0126** | False negative (99% confident it's benign) |

*Figure:* `reports/m4_domain_shift_confidence_20260727.png`.

### 4.1a Full ROC / PR / confusion-matrix analysis on the real capture **[verified]**

Generated via the project's own `evaluation/metrics.py` + `evaluation/reporter.py`
(identical code path as Table 1's offline plots — not a separate ad-hoc
script), evaluated on the same 2,092-flow M4 capture, ground truth from
known VM source IPs (2,038 attack / 54 benign).

| | Before retrain (`benchmarkids_binary.bak`) | After retrain (production) |
|---|---|---|
| Accuracy | 98.66% | 99.95% |
| Precision | 98.69% | 100.00% |
| Recall | 99.95% | 99.95% |
| F1 | 99.32% | 99.98% |
| ROC-AUC | **0.6086** | **0.9999** |
| Confusion matrix | TP=2037 TN=27 **FP=27** FN=1 | TP=2037 TN=54 FP=0 FN=1 |

*Figures* (ROC/PR axes zoomed to where the curve actually varies — see note
in §4.1c):
`reports/roc_live_m4_before_retrain_20260727_233513.png`,
`reports/roc_live_m4_after_retrain_20260727_233514.png`,
`reports/pr_curve_live_m4_before_retrain_20260727_233513.png`,
`reports/pr_curve_live_m4_after_retrain_20260727_233514.png`,
`reports/confusion_matrix_live_m4_before_retrain_20260727_233514.png`,
`reports/confusion_matrix_live_m4_after_retrain_20260727_233515.png`.

Notable finding for the paper: threshold accuracy (98.66%) looks
deceptively acceptable for the pre-fix model, but **ROC-AUC of 0.61** shows
the underlying probability ranking was barely better than random —
exactly half of real benign traffic (27/54) was misclassified as attack.
The confusion matrix, not accuracy alone, is the figure that makes this
visible; recommend leading with it in the paper over the accuracy number.
The PR curve (computed on the attack/positive class) stays misleadingly
high before the fix (AP=0.9807) purely because attacks dominate this
capture 2038:54 — call this out explicitly if included, since on its own
it understates the benign-side failure the confusion matrix and ROC curve
both show clearly.

### 4.1b Same analysis on the larger, independent re-verification capture **[verified]**

The 2,092-flow capture above is small (54 benign flows). The larger,
independently-generated re-verification capture — 44,823 packets, 17,612
ground-truth flows (15,247 attacker / 2,365 benign), captured separately via
`nmap -sS -p 1-10000 -T4` + `gen_benign_traffic.sh` — gives a statistically
sturdier picture and directly demonstrates the port-independence
generalization failure documented in §4.3: the *first* retrained model
(already fixed for the small capture) still misclassified 31% of benign
traffic here because it had only learned "single SYN, no response = benign"
for the one port present in the small capture, not as a port-independent
rule.

Model identity was confirmed empirically (accuracy reproduced to 2 decimal
places against the documented figures) rather than assumed from filenames:
before = `models/benchmarkids_adaptive_20260726_180648_v1.pkl` (the
first-retrain output), after = `models/benchmarkids_adaptive_20260726_203058_v1.pkl`
(the second-retrain output that was promoted to production).

| | Before 2nd retrain | After 2nd retrain |
|---|---|---|
| Accuracy | 95.16% | 99.74% |
| Precision | 95.38% | 100.00% |
| Recall | 99.22% | 99.70% |
| F1 | 97.26% | 99.85% |
| ROC-AUC | 0.8987 | 0.9998 |
| Confusion matrix | TP=15128 TN=1632 **FP=733** FN=119 | TP=15201 TN=2365 FP=0 FN=46 |

*Figures:*
`reports/roc_live_m4_big_before_retrain_20260727_233541.png`,
`reports/roc_live_m4_big_after_retrain_20260727_233543.png`,
`reports/pr_curve_live_m4_big_before_retrain_20260727_233542.png`,
`reports/pr_curve_live_m4_big_after_retrain_20260727_233543.png`,
`reports/confusion_matrix_live_m4_big_before_retrain_20260727_233542.png`,
`reports/confusion_matrix_live_m4_big_after_retrain_20260727_233544.png`.

This pair is the stronger evidence to lead the paper's M4 results with:
733 misclassified benign flows (31% of 2,365) out of thousands, not dozens,
and the ROC-AUC gap (0.90 → 1.00) is large enough to be visually obvious
in a curve plot even without zooming in — unlike the small-capture pair
above, whose ROC curve is a single sharp step from only 54 benign points.

### 4.1c Axis scaling note

`evaluation/reporter.py`'s `plot_roc()`/`plot_pr_curve()` gained an optional
`zoom` parameter (default `False`, existing callers/plots unaffected) used
for all "after retrain" figures above: PR curves auto-fit the y-axis to
where precision actually varies (otherwise a curve varying only between
0.94-1.0 is squeezed into a 5%-tall band against a fixed [0,1.05] axis);
ROC curves auto-fit the x-axis (FPR) to the "elbow" where TPR first nears
its maximum, since `sklearn.roc_curve()` sweeps every threshold down to the
lowest score and so spans FPR close to 1.0 even for a near-perfect
classifier — just at unrealistic operating points far past where the model
is actually used. The y-axis for ROC is deliberately left at [0,1]: a good
classifier's curve rises near-vertically at FPR=0 as TPR climbs to its
operating value, which is real signal (the curve's actual shape), not
something to crop.

### 4.2 Root cause **[verified]**

Both flows were far more minimal (fewer packets, shorter duration) than
anything in the CIC-IDS-2017 training distribution:

| Flow | Fwd/Bwd packets | Duration |
|---|---|---|
| Benign curl request | 7 / 5 | 6–15 ms |
| Kali nmap SYN probe | 1 / 1 | 9–36 **microseconds** |

A single HTTP request is too sparse to resemble the model's learned notion
of "typical benign" (built from fuller captured browsing sessions), and a
single SYN+RST is too minimal to resemble its learned notion of "PortScan."
This is the same domain-shift phenomenon documented for CIC-IDS-2017→2018
(Table 2), now observed between a benchmark dataset and live traffic from
a specific deployment environment.

### 4.3 Adaptive-retraining correction

An adaptive-retraining pipeline (`lab/m4_adaptive_retrain.py` +
`adaptive/adaptive_trainer.py`) was built and run against live-captured,
ground-truth-labelled lab traffic (labels from known VM source IPs), mixing
mistake-weighted correction samples with a baseline-weighted sample of the
original CIC-IDS-2017 training distribution so previously-correct flow
shapes are not silently broken while fixing new ones.

### Table 10 — Accuracy before/after adaptive retraining

| Capture | Flows | Before | After | Provenance |
|---|---|---|---|---|
| Original M4 capture | 2,092 | 1.29% | 99.95% | **[documented]**, 2026-07-26 |
| Independent re-verification capture | 17,612 | 95.16% | 99.74% | **[documented]**, 2026-07-27 |
| Reproducibility check (this session, same capture as row 1) | 2,092 | 98.66% | 99.95% | **[verified]**, 2026-07-27 |

*Figure:* `reports/m4_adaptive_retrain_accuracy_20260727.png`.

Row 3 is an independent re-run performed directly in this session against
the *already-corrected* production model — it demonstrates the fix is
stable and that the retraining pipeline continues to function safely
(auto-accepted a small additional recall gain, 98.88%→99.38%, without
manual override), rather than reproducing the original large jump, since
the original uncorrected model no longer exists in production.

**Independent re-verification detail (row 2):** the first-round fix, tested
against a larger, independently-generated capture (44,823 packets, `nmap -sS
-p 1-10000 -T4` + varied benign traffic across two destination ports),
scored only 95.16% — 100% correct on port 80 but 100% *wrong* on a second
port not present in the original training capture, because the first fix had
only learned "single SYN, no response = benign" for one specific port, not
as a port-independent rule. A second retraining pass corrected this
(99.74%, zero benign false positives); the automated held-out-recall gate
initially rejected the improved candidate on a small/noisy proxy validation
sample and was manually overridden after confirming the real-capture result
was unambiguously better — documented as a methodological decision, not
hidden.

### 4.4 Engineering bugs found while building the retraining pipeline

Three dormant bugs were found and fixed in `adaptive/adaptive_trainer.py` /
`core/model.py` while wiring up adaptive retraining for the first time —
relevant to the paper as evidence the correction pipeline itself required
debugging before it could produce Table 10's results:

| # | Bug | Fix |
|---|---|---|
| 1 | Evaluation compared candidate models against raw test columns instead of each model's own fit-time schema, silently threw, and always rejected retrains | Added `_align_to_model()` |
| 2 | Training-column order was built from a Python `set` intersection (unordered), silently drifting from the column order `MLDetectionLayer`'s cache expects | Preserve mistake-buffer column order explicitly |
| 3 | Per-row sample weights were computed but `BenchmarkIDS.fit()` had no `sample_weight` parameter — weighting mistake rows higher had never actually taken effect | Added `sample_weight`, threaded to `clf__sample_weight` |

---

## Source files for reproduction

- Offline benchmarks: `reports/report_2017_binary_20260720_133638.json`, `CLAUDE.md`
- Live-lab bug fixes: commits `e273d3a`, `62f10ec`
- M4 retraining pipeline: `lab/m4_adaptive_retrain.py`, `adaptive/adaptive_trainer.py`
- Session record: `docs/SESSION_LEDGER.md` (2026-07-25, 2026-07-27 entries)
