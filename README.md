# SENTINEL IPS v2.0

**AI-powered Intrusion Prevention System** — a 13-phase, 31-module pipeline for real-time network threat detection, built as a Major Project (Phase II) and submitted to **Samsung Solve for Tomorrow 2026** under the "AI Living for India" theme, positioned as a democratized cybersecurity solution for schools and MSMEs.

## Performance

| Metric | Score |
|---|---|
| Accuracy | 99.83% |
| F1 Score | 99.67% |
| AUC | 100% |
| Throughput | ~1.1M flows/sec |

Benchmarked on CIC-IDS-2017 and CIC-IDS-2018 datasets.

## Architecture

SENTINEL IPS is organized as a layered detection and response pipeline:

- **`detection/`** — Three-layer detection: ML-based (XGBoost), signature-based, and anomaly-based
- **`core/`** — Feature engineering, preprocessing, and model management
- **`adaptive/`** — Adaptive retraining, mistake collection, zero-day pattern mining
- **`attribution/`** — Geolocation, MITRE ATT&CK mapping, threat actor profiling
- **`intelligence/`** — IP/domain reputation feeds, honeypot integration, threat intel
- **`explainability/`** — SHAP-based explainability, attack narration, risk scoring
- **`forensics/`** — Packet logging, timeline reconstruction, compliance reporting (GDPR, ISO)
- **`response/`** — Automated response: IP blacklisting, rate limiting, connection termination
- **`dashboard/`** — Real-time monitoring dashboard (Streamlit) with live attack map
- **`evaluation/`** — Metrics computation and automated reporting

## Tech Stack

Python · XGBoost · scikit-learn · SHAP · Streamlit · Plotly · pandas · NumPy

## Getting Started

Windows prerequisite for live capture (`sentinel.py live`): install
[Npcap](https://npcap.com/) with "WinPcap API-compatible Mode" checked, and
run from an elevated (Administrator) shell unless Npcap was installed
without the admin-only access restriction. See `lab/README.md` for the
full live-traffic validation lab setup.

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python sentinel.py health
```

Run the dashboard:
```bash
streamlit run dashboard/app.py
```

Run the demo:
```bash
python demo.py
```

## Reports & Explainability

The \eports/\ directory contains generated confusion matrices, ROC curves, PR curves, and compliance reports (GDPR/ISO format). The \shap_plots/\ directory contains SHAP-based model explainability visualizations.

## Note

Trained model files and the CIC-IDS datasets are excluded from this repository due to size. Models can be regenerated via \	rain.py\ given access to the CIC-IDS-2017/2018 datasets, or are available on request.

## Author

**MT Yashas** (USN: 1GA23CS091) — B.E. Computer Science & Engineering, Global Academy of Technology, Bengaluru
