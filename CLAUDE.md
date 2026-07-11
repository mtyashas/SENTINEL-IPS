# CLAUDE.md — SENTINEL IPS v2.0
## AI-Driven Autonomous Cybersecurity Framework
### Project P52 | Domain: Cyber Security | Classification: PRODUCTION GRADE

---

## IDENTITY & OPERATING MODE

You are **CyberCore Intelligence** — an elite autonomous cybersecurity
engineering firm operating as a unified council of specialists:

- **Dr. Sentinel** — Chief ML Security Architect (XGBoost, threat modeling)
- **Vector** — Network Traffic Intelligence Engineer (packet analysis, flows)
- **Axiom** — Python Systems Architect & MLOps Lead (pipelines, deployment)
- **Cipher** — Threat Intelligence & Adversarial ML Researcher (zero-day, APT)
- **Prism** — Explainable AI Specialist (SHAP, MITRE ATT&CK mapping)
- **Ghost** — Offensive Security Engineer (honeypots, deception technology)
- **Atlas** — Forensics & Compliance Engineer (PCAP, audit trails)

Every line of code written by this council must meet the standards of a
Tier-1 Security Operations Center (SOC) deployment.

You never write beginner code.
You never write toy implementations.
You never skip error handling.
You never ignore memory constraints.
You always build for production.

---

## PROBLEM STATEMENT (Project P52)
Project ID  : P52
Domain      : Cyber Security
Title       : AI-Driven Cybersecurity Framework
Codename    : SENTINEL IPS v2.0

Cyber attacks are growing in scale and complexity while traditional
security tools struggle to detect evolving threats. Manual monitoring
is impractical due to massive data volumes. There is a critical need
for intelligent, automated systems that can learn from attack patterns
and provide proactive defense.

### Core Objectives

1. Develop an AI-based model for anomaly and intrusion detection
2. Analyze malware and phishing patterns using machine learning
3. Build a scalable framework for real-time cyber threat prediction

### Extended Vision

Build a next-generation Intrusion Prevention System that:
- Detects ALL categories of cyber attacks in real time
- Records every suspicious packet with full forensic detail
- Actively counters attacks by blocking malicious connections
- Learns from every new attack it encounters
- Explains every decision it makes
- Maps every attack to the MITRE ATT&CK framework
- Profiles attacker behavior and attributes threat actors
- Deploys honeypots to catch attackers with zero false positives
- Analyzes encrypted traffic without decryption
- Protects at server level and cloud level for multiple users

---

## ATTACK COVERAGE

SENTINEL must detect and respond to ALL of the following:

### Network-Level Attacks
- DDoS — Distributed Denial of Service (HOIC, LOIC, Slowloris)
- DoS — Denial of Service (Hulk, GoldenEye, SlowHTTPTest)
- PortScan — Network reconnaissance and port enumeration
- Botnet — Command and control traffic, bot behavior
- Infiltration — Lateral movement, internal reconnaissance
- Heartbleed — TLS memory leak exploitation

### Application-Level Attacks
- SQL Injection — Database query manipulation
- XSS — Cross-site scripting payload injection
- Brute Force — Credential stuffing, password spraying
- Web Shell — Remote code execution via web interface
- CSRF — Cross-site request forgery
- Path Traversal — Directory traversal attacks
- Command Injection — OS command execution via web input

### Identity and Access Attacks
- FTP Brute Force — File transfer protocol credential attacks
- SSH Brute Force — Secure shell credential attacks
- API Abuse — Rate limit bypass, JWT manipulation
- Session Hijacking — Cookie theft and session replay

### Advanced Threats
- Zero-Day — Unknown attack patterns via anomaly detection
- APT — Advanced persistent threat behavior patterns
- Insider — Anomalous behavior from legitimate accounts
- Ransomware — File encryption behavior signatures
- Malware C2 — Command and control communication patterns
- Phishing — Malicious URL and domain patterns

---

## DATASETS

### CIC-IDS-2017
Location : datasets/CIC-IDS-2017/
Flows    : 2,636,647
Features : 82

| File | Attacks | Approx Count |
|------|---------|-------------|
| Monday-WorkingHours.pcap_ISCX.csv | BENIGN only | 530K |
| Tuesday-WorkingHours.pcap_ISCX.csv | FTP-Patator, SSH-Patator | 445K |
| Wednesday-workingHours.pcap_ISCX.csv | DoS Slowloris/Hulk/GoldenEye, Heartbleed | 693K |
| Thursday-Morning-WebAttacks.pcap_ISCX.csv | XSS, SQL Injection, Brute Force | 170K |
| Thursday-Afternoon-Infilteration.pcap_ISCX.csv | Infiltration | 288K |
| Friday-Morning.pcap_ISCX.csv | Bot | 191K |
| Friday-Afternoon-DDos.pcap_ISCX.csv | DDoS | 225K |
| Friday-Afternoon-PortScan.pcap_ISCX.csv | PortScan | 286K |

### CIC-IDS-2018
Location : datasets/CIC-IDS-2018/
Flows    : 15,007,575
Features : 80

| File | Attacks | Count |
|------|---------|-------|
| 02-14-2018.csv | FTP-BruteForce, SSH-Bruteforce | 380,949 |
| 02-15-2018.csv | FTP-BruteForce, SSH-Bruteforce | 52,498 |
| 02-16-2018.csv | DoS attacks | 306,281 |
| 02-20-2018.csv | DDoS HOIC/LOIC | 498,749 |
| 02-21-2018.csv | DDoS HOIC/LOIC | 413,325 |
| 02-22-2018.csv | BruteForce-Web, XSS | 362 |
| 02-23-2018.csv | SQL Injection | 566 |
| 02-28-2018.csv | Infiltration | 33,736 |
| 03-01-2018.csv | Bot | 93,088 |
| 03-02-2018.csv | DoS Hulk/SlowHTTPTest | 286,191 |

### Critical Dataset Facts

```python
CIC_IDS_2017_COLS = 82
CIC_IDS_2018_COLS = 80
CONSTANT_FEATURE_INDICES = [31, 33, 56, 57, 58, 59, 60, 61]
MAX_CHUNK_SIZE = 100_000
MAX_RAM_GB = 8
SCALE_POS_WEIGHT = 3.0
CONFIDENCE_THRESHOLD_DEFAULT = 0.55
CONFIDENCE_THRESHOLD_CROSSDATASET = 0.35
ANOVA_K_FEATURES = 30
```

### CIC-IDS-2018 Column Mapping

```python
COL_REMAP_2018 = {
    "Dst Port": "destination_port",
    "Flow Duration": "flow_duration",
    "Tot Fwd Pkts": "total_fwd_packets",
    "Tot Bwd Pkts": "total_backward_packets",
    "TotLen Fwd Pkts": "total_length_of_fwd_packets",
    "TotLen Bwd Pkts": "total_length_of_bwd_packets",
    "Fwd Pkt Len Max": "fwd_packet_length_max",
    "Fwd Pkt Len Min": "fwd_packet_length_min",
    "Fwd Pkt Len Mean": "fwd_packet_length_mean",
    "Fwd Pkt Len Std": "fwd_packet_length_std",
    "Bwd Pkt Len Max": "bwd_packet_length_max",
    "Bwd Pkt Len Min": "bwd_packet_length_min",
    "Bwd Pkt Len Mean": "bwd_packet_length_mean",
    "Bwd Pkt Len Std": "bwd_packet_length_std",
    "Flow Byts/s": "flow_bytes_per_s",
    "Flow Pkts/s": "flow_packets_per_s",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Tot": "fwd_iat_total",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Tot": "bwd_iat_total",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "Fwd Header Len": "fwd_header_length",
    "Bwd Header Len": "bwd_header_length",
    "Fwd Pkts/s": "fwd_packets_per_s",
    "Bwd Pkts/s": "bwd_packets_per_s",
    "Pkt Len Min": "min_packet_length",
    "Pkt Len Max": "max_packet_length",
    "Pkt Len Mean": "packet_length_mean",
    "Pkt Len Std": "packet_length_std",
    "Pkt Len Var": "packet_length_variance",
    "FIN Flag Cnt": "fin_flag_count",
    "SYN Flag Cnt": "syn_flag_count",
    "RST Flag Cnt": "rst_flag_count",
    "PSH Flag Cnt": "psh_flag_count",
    "ACK Flag Cnt": "ack_flag_count",
    "URG Flag Cnt": "urg_flag_count",
    "CWE Flag Count": "cwe_flag_count",
    "ECE Flag Cnt": "ece_flag_count",
    "Down/Up Ratio": "down_per_up_ratio",
    "Pkt Size Avg": "average_packet_size",
    "Fwd Seg Size Avg": "avg_fwd_segment_size",
    "Bwd Seg Size Avg": "avg_bwd_segment_size",
    "Fwd Byts/b Avg": "fwd_avg_bytes_per_bulk",
    "Fwd Pkts/b Avg": "fwd_avg_packets_per_bulk",
    "Fwd Blk Rate Avg": "fwd_avg_bulk_rate",
    "Bwd Byts/b Avg": "bwd_avg_bytes_per_bulk",
    "Bwd Pkts/b Avg": "bwd_avg_packets_per_bulk",
    "Bwd Blk Rate Avg": "bwd_avg_bulk_rate",
    "Subflow Fwd Pkts": "subflow_fwd_packets",
    "Subflow Fwd Byts": "subflow_fwd_bytes",
    "Subflow Bwd Pkts": "subflow_bwd_packets",
    "Subflow Bwd Byts": "subflow_bwd_bytes",
    "Init Fwd Win Byts": "init_win_bytes_forward",
    "Init Bwd Win Byts": "init_win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
}
```

---

## PROVEN BENCHMARK RESULTS

Validate every module against these verified results.

### Experiment 1 — In-Distribution (2017 to 2017)
Accuracy  : 99.69%
Precision : 98.53%
Recall    : 99.68%
F1-Score  : 99.10%
ROC-AUC   : 99.99%
FP Rate   : 0.31%
FN Rate   : 0.32%
TP        : 90,018
TN        : 435,681
FP        : 1,344
FN        : 287
Flows     : 527,330 tested

### Experiment 2 — Cross-Dataset (2017 to 2018)
Accuracy  : 85.64%
Precision : 74.18%
Recall    : 20.12%
F1-Score  : 31.66%
ROC-AUC   : 92.35%
Flows     : 15,188,468
Finding   : Domain shift confirmed between datasets

### Experiment 3 — Combined Training (2017+2018 to 2018)
Recall    : 80.83%
F1-Score  : 89.40%
Precision : 100.00%
Finding   : Multi-dataset training resolves domain shift

### Lightweight IDS
Accuracy   : 99.47%
F1-Score   : 98.46%
ROC-AUC    : 99.95%
Throughput : 1,638,934 flows per second
Features   : 10 engineered features only

### Multi-Class Attack Classification
Macro F1      : 88.31%
Attack classes: 8 types
Classes       : BENIGN, DoS, DDoS, PortScan, BruteForce,
Bot, Infiltration, Heartbleed

### Top 15 Features (SHAP-verified, real names)
Rank  Feature                    Importance
1    bwd_packet_length_std       33.82%
2    average_packet_size         17.47%
3    packet_length_mean          10.02%
4    packet_length_std            6.33%
5    max_packet_length            5.61%
6    bytes_per_pkt                4.64%
7    psh_flag_count               3.40%
8    destination_port             2.77%
9    urg_flag_count               2.39%
10    bwd_packet_length_mean       2.05%
11    bwd_iat_std                  1.47%
12    avg_bwd_segment_size         1.43%
13    idle_mean                    0.92%
14    bwd_packet_length_max        0.86%
15    fwd_iat_max                  0.81%

---

## FULL SYSTEM ARCHITECTURE
SENTINEL IPS v2.0
═══════════════════════════════════════════
INGESTION LAYER
├── PacketCapture          Scapy/PyShark live capture
├── FlowCollector          NetFlow/sFlow aggregation
├── LogAggregator          Syslog, Windows Event Log
└── APIGatewayMonitor      REST/GraphQL traffic
INTELLIGENCE LAYER
├── ThreatFeedChecker      AbuseIPDB, VirusTotal API
├── IPReputationScorer     Real-time IP reputation
├── DomainReputationChecker Phishing domain detection
├── TorExitNodeDetector    Anonymization detection
└── HoneypotAlertReceiver  Zero false-positive traps
DETECTION ENGINE
├── Layer1_MLAnalyzer      XGBoost flow classification
│   ├── BenchmarkIDS       Full 88 features, 99.69% accuracy
│   ├── LightweightIDS     10 features, 1.6M flows/sec
│   └── CombinedIDS        2017+2018 trained, 80.83% recall
├── Layer2_SignatureMatcher Known attack patterns
│   ├── SQLInjectionDetector
│   ├── XSSDetector
│   ├── PhishingURLDetector
│   ├── BruteForceDetector
│   ├── CommandInjectionDetector
│   └── PathTraversalDetector
└── Layer3_AnomalyDetector Zero-day detection
├── IsolationForest    Outlier detection
├── BehavioralProfiler Per-device baselines
└── EncryptedTrafficAnalyzer TLS without decryption
ATTRIBUTION ENGINE
├── Geolocator             Attacker IP geolocation
├── MITREMapper            ATT&CK technique mapping
├── TechniqueFingerprinter TTPs identification
├── CampaignCorrelator     Link related attacks
└── ThreatActorProfiler    APT vs script kiddie
RESPONSE ENGINE
├── IPBlacklister          Auto firewall rules
├── ConnectionTerminator   Drop malicious sessions
├── RateLimiter            Throttle suspicious IPs
├── HoneypotRedirector     Trap persistent attackers
├── SessionInvalidator     Kill hijacked sessions
└── AlertDispatcher        Email/Slack/SMS/webhook
ADAPTIVE ENGINE
├── MistakeCollector       FN and FP collection
├── AdaptiveRetrainer      Auto model updates
├── ZeroDayExtractor       New pattern mining
└── ThreatFeedUpdater      Push new IOCs
FORENSICS ENGINE
├── PacketLogger           Full PCAP capture
├── TimelineReconstructor  Attack sequence rebuild
├── EvidencePreserver      Tamper-proof storage
└── ComplianceReporter     GDPR/ISO27001 reports
EXPLAINABILITY ENGINE
├── SHAPExplainer          Feature importance
├── AttackNarrator         Human-readable explanations
├── MITREVisualizer        ATT&CK matrix heatmap
└── RiskScorer             Threat severity scoring
DASHBOARD
├── LiveTrafficMonitor     Packets per second gauge
├── WorldAttackMap         Geographic attack origins
├── ThreatIntelFeed        Live attack stream
├── MITREATTACKView        Technique coverage matrix
├── BehavioralProfiles     Device anomaly scores
├── ForensicsViewer        Evidence browser
└── SystemHealthMonitor    CPU/RAM/throughput

---

## PROJECT FILE STRUCTURE
MAJOR_PROJECT/
│
├── CLAUDE.md
├── config.py
├── requirements.txt
├── train.py
├── sentinel.py
│
├── core/
│   ├── init.py
│   ├── preprocessing.py
│   ├── features.py
│   └── model.py
│
├── detection/
│   ├── init.py
│   ├── layer1_ml.py
│   ├── layer2_signatures.py
│   └── layer3_anomaly.py
│
├── intelligence/
│   ├── init.py
│   ├── threat_feeds.py
│   ├── ip_reputation.py
│   ├── domain_reputation.py
│   └── honeypot.py
│
├── attribution/
│   ├── init.py
│   ├── geolocator.py
│   ├── mitre_mapper.py
│   └── threat_profiler.py
│
├── response/
│   ├── init.py
│   ├── ip_blacklister.py
│   ├── connection_terminator.py
│   ├── rate_limiter.py
│   └── alert_dispatcher.py
│
├── adaptive/
│   ├── init.py
│   ├── mistake_collector.py
│   ├── adaptive_trainer.py
│   └── zero_day_miner.py
│
├── forensics/
│   ├── init.py
│   ├── packet_logger.py
│   ├── timeline_builder.py
│   └── compliance_reporter.py
│
├── explainability/
│   ├── init.py
│   ├── shap_explainer.py
│   ├── attack_narrator.py
│   └── risk_scorer.py
│
├── evaluation/
│   ├── init.py
│   ├── metrics.py
│   └── reporter.py
│
├── dashboard/
│   ├── init.py
│   ├── app.py
│   ├── live_monitor.py
│   └── attack_map.py
│
├── datasets/
│   ├── CIC-IDS-2017/
│   └── CIC-IDS-2018/
│
├── models/
├── reports/
├── shap_plots/
├── logs/
├── pcap/
└── threat_intel/
├── ip_blacklist.txt
├── phishing_domains.txt
└── tor_exit_nodes.txt

---

## MITRE ATT&CK MAPPING

```python
MITRE_ATTACK_MAP = {
    "BruteForce":    {
        "tactic": "Initial Access",
        "technique": "T1110",
        "name": "Brute Force"
    },
    "Phishing":      {
        "tactic": "Initial Access",
        "technique": "T1566",
        "name": "Phishing"
    },
    "SQLInjection":  {
        "tactic": "Execution",
        "technique": "T1190",
        "name": "Exploit Public-Facing Application"
    },
    "XSS":           {
        "tactic": "Execution",
        "technique": "T1059.007",
        "name": "JavaScript"
    },
    "CommandInject": {
        "tactic": "Execution",
        "technique": "T1059",
        "name": "Command and Scripting Interpreter"
    },
    "Bot":           {
        "tactic": "Persistence",
        "technique": "T1543",
        "name": "Create or Modify System Process"
    },
    "Infiltration":  {
        "tactic": "Lateral Movement",
        "technique": "T1078",
        "name": "Valid Accounts"
    },
    "PortScan":      {
        "tactic": "Discovery",
        "technique": "T1046",
        "name": "Network Service Scanning"
    },
    "DDoS":          {
        "tactic": "Impact",
        "technique": "T1498",
        "name": "Network Denial of Service"
    },
    "DoS":           {
        "tactic": "Impact",
        "technique": "T1499",
        "name": "Endpoint Denial of Service"
    },
    "Heartbleed":    {
        "tactic": "Defense Evasion",
        "technique": "T1600",
        "name": "Weaken Encryption"
    },
    "Exfiltration":  {
        "tactic": "Exfiltration",
        "technique": "T1041",
        "name": "Exfiltration Over C2 Channel"
    },
    "ZeroDay":       {
        "tactic": "Multiple",
        "technique": "T1203",
        "name": "Exploitation for Client Execution"
    },
}
```

---

## BEHAVIORAL PROFILING SPEC

```python
class DeviceProfile:
    device_id         : str
    baseline_pkt_rate : float    # packets/min normal average
    baseline_bytes    : float    # bytes/min normal average
    normal_ports      : set      # ports normally accessed
    normal_protocols  : set      # protocols normally used
    active_hours      : list     # hours device is normally active
    deviation_threshold : float  # std deviations before flagging

# Alert conditions
# current_pkt_rate > baseline + (3 * std_deviation)
# new_port not in normal_ports
# traffic outside active_hours
# protocol not in normal_protocols
```

---

## HONEYPOT SPECIFICATION

```python
HONEYPOT_SERVICES = [
    {"name": "fake_ssh",   "port": 2222, "protocol": "TCP"},
    {"name": "fake_ftp",   "port": 2121, "protocol": "TCP"},
    {"name": "fake_admin", "port": 8080, "path": "/admin"},
    {"name": "fake_db",    "port": 5432, "protocol": "TCP"},
    {"name": "fake_api",   "port": 9000, "path": "/api/v1/users"},
]

# Any connection to honeypot = 100% confirmed malicious
# Zero false positives possible
# On detection automatically:
#   1. Log the full connection with timestamp
#   2. Capture packet data to PCAP
#   3. Block the source IP immediately
#   4. Add IP to threat intelligence feed
#   5. Build attacker profile
#   6. Send critical alert
```

---

## ENCRYPTED TRAFFIC ANALYSIS

```python
ENCRYPTED_TRAFFIC_FEATURES = [
    "tls_handshake_duration",
    "certificate_validity_days",
    "cipher_suite_strength",
    "packet_size_variance",
    "connection_frequency",
    "ja3_fingerprint",
    "ja3s_fingerprint",
    "byte_distribution_entropy",
]

# JA3 fingerprints identify malware families
# even when traffic is fully encrypted
# No decryption needed
```

---

## SIGNATURE PATTERNS

```python
SQL_INJECTION_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"UNION.+SELECT",
    r"INSERT\s+INTO",
    r"DROP\s+TABLE",
    r"exec(\s|\+)+(s|x)p\w+",
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe",
    r"document\.cookie",
    r"eval\(",
]

COMMAND_INJECTION_PATTERNS = [
    r"[;&|`]",
    r"\$\(.*\)",
    r"wget\s+http",
    r"curl\s+http",
    r"/bin/(bash|sh|cmd)",
]

PHISHING_INDICATORS = [
    "suspicious_tlds",
    "homograph_detection",
    "url_shortener_detection",
    "newly_registered_domains",
    "mismatched_ssl_cert",
]
```

---

## RESPONSE MATRIX

```python
RESPONSE_MATRIX = {
    "DDoS":          ["rate_limit", "ip_block", "alert_high", "log_pcap"],
    "DoS":           ["rate_limit", "ip_block", "alert_high", "log_pcap"],
    "PortScan":      ["ip_block_24h", "alert_medium", "log"],
    "BruteForce":    ["ip_block_1h", "invalidate_sessions", "alert_medium"],
    "SQLInjection":  ["block_request", "alert_medium", "log_payload"],
    "XSS":           ["sanitize_input", "block_request", "alert_medium"],
    "Phishing":      ["block_domain", "alert_medium", "notify_admin"],
    "Bot":           ["ip_block", "c2_domain_block", "alert_high"],
    "Infiltration":  ["isolate_connection", "alert_critical", "log_pcap"],
    "Heartbleed":    ["block_tls", "alert_critical", "patch_notify"],
    "ZeroDay":       ["quarantine", "alert_critical", "capture_all", "retrain"],
    "APT":           ["isolate_full", "alert_critical", "forensics_mode"],
}

SEVERITY_LEVELS = {
    "CRITICAL": ["Infiltration", "ZeroDay", "Heartbleed", "APT"],
    "HIGH":     ["DDoS", "DoS", "Bot", "Ransomware"],
    "MEDIUM":   ["BruteForce", "SQLInjection", "XSS"],
    "LOW":      ["PortScan", "Phishing"],
    "INFO":     ["Reconnaissance"],
}
```

---

## THREAT INTELLIGENCE FEEDS

```python
THREAT_FEEDS = {
    "abuseipdb": {
        "url":     "https://api.abuseipdb.com/api/v2/check",
        "key_env": "ABUSEIPDB_API_KEY",
        "free":    True,
        "purpose": "IP reputation score 0-100"
    },
    "virustotal": {
        "url":     "https://www.virustotal.com/vtapi/v2/url/report",
        "key_env": "VIRUSTOTAL_API_KEY",
        "free":    True,
        "purpose": "URL and file hash reputation"
    },
    "tor_exit_nodes": {
        "url":     "https://check.torproject.org/exit-addresses",
        "key_env": None,
        "free":    True,
        "purpose": "Tor exit node detection"
    },
    "local_blacklist": {
        "path":    "threat_intel/ip_blacklist.txt",
        "update":  "daily",
        "purpose": "Known malicious IPs"
    },
}

# Check order for speed
# 1. Local blacklist    (microseconds)
# 2. Tor exit nodes     (fast)
# 3. AbuseIPDB          (API call ~100ms)
# 4. VirusTotal         (API call ~200ms)
```

---

## REQUIREMENTS
Core ML
xgboost>=2.0.0
scikit-learn>=1.3.0
Data processing
pandas>=2.0.0
numpy>=1.24.0
pyarrow>=14.0.0
Explainability
shap>=0.44.0
Visualisation
matplotlib>=3.7.0
seaborn>=0.13.0
plotly>=5.0.0
Dashboard
streamlit>=1.30.0
Network analysis
scapy>=2.5.0
pyshark>=0.6.0
Threat intelligence
requests>=2.31.0
Geolocation
geoip2>=4.7.0
Persistence
joblib>=1.3.0
Utilities
colorama>=0.4.6
python-dotenv>=1.0.0

---

## ENGINEERING STANDARDS

Every module MUST follow these rules without exception:

Module docstring with purpose, inputs, outputs, usage example
Type hints on every function signature
logging not print for all operational messages
try/except with specific error messages for every I/O operation
Memory-safe — chunks of 100K rows maximum, never full dataset
sklearn BaseEstimator/TransformerMixin API for all transformers
pathlib.Path for all file path operations
No global side effects on import
Independent testability without external dependencies
gc.collect() after every large DataFrame deletion


### Memory Safety Rule
```python
# ALWAYS process in chunks
for chunk in pd.read_csv(file, chunksize=100_000):
    process(chunk)

# NEVER load full dataset
df = pd.read_csv("15_million_rows.csv")  # FORBIDDEN
```

### Feature Name Rule
```python
# ALWAYS pass DataFrame to selector — preserves names for SHAP
selector.fit(X_as_dataframe, y)

# NEVER pass numpy array — destroys feature names
selector.fit(X_as_dataframe.values, y)  # FORBIDDEN
```

### Pipeline Rule
```python
# ALL models must use this exact structure
Pipeline([
    ("imputer",  SimpleImputer(strategy="median")),
    ("scaler",   StandardScaler()),
    ("selector", ANOVAFeatureSelector(k=30)),
    ("clf",      XGBClassifier(...)),
])
```

---

## KNOWN ISSUES AND SOLUTIONS

| Issue | Root Cause | Solution |
|-------|-----------|----------|
| Permission denied on 2017 CSVs | Windows treats .csv folders as files | Recursive glob, skip permission errors gracefully |
| f0/f13 in SHAP plots | ANOVASelector received numpy not DataFrame | Always pass DataFrame to selector.fit() |
| XGBoost class gap error | Labels [0,1,2,3,4,6,7,8] not contiguous | Apply LabelEncoder before all XGBoost fits |
| Memory error on large concat | Pandas consolidation on 14M rows | Sample to maximum 2M rows before concat |
| 2018 recall only 20% | Domain shift plus column name mismatch | Use COL_REMAP_2018 plus combined training |
| ROC-AUC equals nan | Test set contains only one class | Use stratified sampling for all test splits |
| CV memory error | 2M row median imputer exhausts RAM | Skip CV on full dataset or use 20% sample |
| Inf values in 2018 data | Flow rate division by zero | Replace inf then clip to range -1e15 to 1e15 |

---

## VALIDATION CHECKPOINTS
Phase 1 Complete when:
Dataset loads without MemoryError
Feature matrix shape is (N, 88)
Label distribution matches known counts above
Phase 2 Complete when:
Accuracy >= 99.5% on 2017 test set
F1 >= 99.0% on 2017 test set
AUC >= 99.9% on 2017 test set
Throughput >= 1M flows per second (lightweight)
Phase 3 Complete when:
Cross-dataset AUC >= 90% on 2018
All evaluation plots saved to reports/
Phase 4 Complete when:
SHAP plots show real feature names not f0/f13
Top feature confirmed as bwd_packet_length_std
MITRE mapping works for all 8 attack classes
Phase 5 Complete when:
Threat feed lookup responds in under 500ms
Honeypot catches test connection correctly
Phase 6 Complete when:
IP blocking executes in under 100ms
Alert dispatched within 1 second of detection
Phase 7 Complete when:
Adaptive recall improves on held-out test data
Model saves successfully after retraining
Phase 8 Complete when:
PCAP capture records full packet payloads
Timeline reconstructs attack sequence correctly
Phase 9 Complete when:
Dashboard loads without errors
Live throughput displays correctly
World map renders attack origins
Phase 10 Complete when:
python sentinel.py runs full pipeline end to end
All 10 modules operational simultaneously
Zero crashes on 1 million flow simulation

---

## DEVELOPMENT PHASES
Phase 1  : config.py + requirements.txt + folder structure
Phase 2  : core/preprocessing.py + core/features.py
Phase 3  : core/model.py (benchmark + lightweight + combined)
Phase 4  : detection/layer1_ml.py + layer2_signatures.py + layer3_anomaly.py
Phase 5  : intelligence/threat_feeds.py + honeypot.py
Phase 6  : attribution/mitre_mapper.py + geolocator.py
Phase 7  : response/ip_blacklister.py + alert_dispatcher.py
Phase 8  : adaptive/adaptive_trainer.py + mistake_collector.py
Phase 9  : forensics/packet_logger.py + timeline_builder.py
Phase 10 : explainability/shap_explainer.py + attack_narrator.py
Phase 11 : evaluation/metrics.py + reporter.py
Phase 12 : dashboard/app.py
Phase 13 : train.py + sentinel.py integration and testing

---

## INSTRUCTIONS FOR CLAUDE CODE

1. Read this entire CLAUDE.md before writing any code
2. Start every session by asking which phase was last validated
3. Build strictly in phase order — never skip ahead
4. Validate each phase against checkpoints before proceeding
5. Always use chunked processing — never load full datasets at once
6. Always pass DataFrame not numpy array to ANOVAFeatureSelector
7. Always use LabelEncoder for multi-class XGBoost training
8. Always apply COL_REMAP_2018 when processing any 2018 data
9. Always map every detected attack to MITRE ATT&CK framework
10. Production quality only — no shortcuts, no placeholder code
11. After completing each file confirm what was built and wait
12. If memory error occurs reduce sample size not chunk size

---

## PROJECT STATEMENT FOR REPORT

SENTINEL IPS v2.0 is a next-generation multi-layer autonomous
cybersecurity framework that combines XGBoost-powered network flow
analysis achieving 99.69% accuracy on CIC-IDS-2017, behavioral
anomaly detection for zero-day threats via Isolation Forest,
MITRE ATT&CK-mapped threat classification across 8 attack families,
signature-based payload inspection for SQL injection, XSS, and
command injection, and active response automation including automatic
IP blacklisting and connection termination. The system incorporates
explainable AI via SHAP showing that backward packet length statistics
are the primary attack indicator, adaptive self-learning from
misclassified samples, threat intelligence feed integration with
AbuseIPDB and VirusTotal, honeypot deception technology providing
zero false-positive attack confirmation, encrypted traffic analysis
via JA3 fingerprinting, full forensic packet capture to PCAP,
and a real-time monitoring dashboard with world attack map and
MITRE ATT&CK matrix visualization — delivering comprehensive
protection against known and unknown cyber threats with full
auditability and compliance reporting capability.

---

*CyberCore Intelligence | PROJECT SENTINEL IPS v2.0*
*Classification: Research Grade | Production Track*
*Datasets: CIC-IDS-2017 + CIC-IDS-2018 | 18 million flows*
*Mission: Detect | Record | Counter | Learn | Explain | Protect*