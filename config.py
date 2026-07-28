"""
SENTINEL IPS v2.0 — Master Configuration
CyberCore Intelligence | Project P52

Central registry for all paths, hyperparameters, label maps, attack taxonomies,
MITRE ATT&CK mappings, response directives, and operational constants.
Every module imports exclusively from this file — never hardcode values elsewhere.

Usage:
    from config import ROOT, COL_REMAP_2018, CHUNK_SIZE, MITRE_ATTACK_MAP
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# A. DIRECTORY PATHS
# ---------------------------------------------------------------------------

ROOT       = Path(__file__).parent
MODEL_DIR  = ROOT / "models"
REPORT_DIR = ROOT / "reports"
SHAP_DIR   = ROOT / "shap_plots"
LOG_DIR    = ROOT / "logs"
PCAP_DIR   = ROOT / "pcap"
THREAT_DIR = ROOT / "threat_intel"
DATA_2017  = ROOT / "datasets" / "CIC-IDS-2017"
DATA_2018  = ROOT / "datasets" / "CIC-IDS-2018"

# Ensure output directories exist at import time (safe, no side effects on data dirs)
for _d in (MODEL_DIR, REPORT_DIR, SHAP_DIR, LOG_DIR, PCAP_DIR, THREAT_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# B. XGBOOST HYPERPARAMETERS
# ---------------------------------------------------------------------------

XGB_PARAMS = {
    "n_estimators":      500,
    "max_depth":         8,
    "learning_rate":     0.05,
    "subsample":         0.8,
    "colsample_bytree":  0.8,
    "eval_metric":       "logloss",
    "n_jobs":            -1,
    "random_state":      42,
}

# ---------------------------------------------------------------------------
# C. CIC-IDS-2018 COLUMN RENAME MAP
# ---------------------------------------------------------------------------

COL_REMAP_2018 = {
    "Dst Port":           "destination_port",
    "Flow Duration":      "flow_duration",
    "Tot Fwd Pkts":       "total_fwd_packets",
    "Tot Bwd Pkts":       "total_backward_packets",
    "TotLen Fwd Pkts":    "total_length_of_fwd_packets",
    "TotLen Bwd Pkts":    "total_length_of_bwd_packets",
    "Fwd Pkt Len Max":    "fwd_packet_length_max",
    "Fwd Pkt Len Min":    "fwd_packet_length_min",
    "Fwd Pkt Len Mean":   "fwd_packet_length_mean",
    "Fwd Pkt Len Std":    "fwd_packet_length_std",
    "Bwd Pkt Len Max":    "bwd_packet_length_max",
    "Bwd Pkt Len Min":    "bwd_packet_length_min",
    "Bwd Pkt Len Mean":   "bwd_packet_length_mean",
    "Bwd Pkt Len Std":    "bwd_packet_length_std",
    "Flow Byts/s":        "flow_bytes_per_s",
    "Flow Pkts/s":        "flow_packets_per_s",
    "Flow IAT Mean":      "flow_iat_mean",
    "Flow IAT Std":       "flow_iat_std",
    "Flow IAT Max":       "flow_iat_max",
    "Flow IAT Min":       "flow_iat_min",
    "Fwd IAT Tot":        "fwd_iat_total",
    "Fwd IAT Mean":       "fwd_iat_mean",
    "Fwd IAT Std":        "fwd_iat_std",
    "Fwd IAT Max":        "fwd_iat_max",
    "Fwd IAT Min":        "fwd_iat_min",
    "Bwd IAT Tot":        "bwd_iat_total",
    "Bwd IAT Mean":       "bwd_iat_mean",
    "Bwd IAT Std":        "bwd_iat_std",
    "Bwd IAT Max":        "bwd_iat_max",
    "Bwd IAT Min":        "bwd_iat_min",
    "Fwd PSH Flags":      "fwd_psh_flags",
    "Bwd PSH Flags":      "bwd_psh_flags",
    "Fwd URG Flags":      "fwd_urg_flags",
    "Bwd URG Flags":      "bwd_urg_flags",
    "Fwd Header Len":     "fwd_header_length",
    "Bwd Header Len":     "bwd_header_length",
    "Fwd Pkts/s":         "fwd_packets_per_s",
    "Bwd Pkts/s":         "bwd_packets_per_s",
    "Pkt Len Min":        "min_packet_length",
    "Pkt Len Max":        "max_packet_length",
    "Pkt Len Mean":       "packet_length_mean",
    "Pkt Len Std":        "packet_length_std",
    "Pkt Len Var":        "packet_length_variance",
    "FIN Flag Cnt":       "fin_flag_count",
    "SYN Flag Cnt":       "syn_flag_count",
    "RST Flag Cnt":       "rst_flag_count",
    "PSH Flag Cnt":       "psh_flag_count",
    "ACK Flag Cnt":       "ack_flag_count",
    "URG Flag Cnt":       "urg_flag_count",
    "CWE Flag Count":     "cwe_flag_count",
    "ECE Flag Cnt":       "ece_flag_count",
    "Down/Up Ratio":      "down_per_up_ratio",
    "Pkt Size Avg":       "average_packet_size",
    "Fwd Seg Size Avg":   "avg_fwd_segment_size",
    "Bwd Seg Size Avg":   "avg_bwd_segment_size",
    "Fwd Byts/b Avg":     "fwd_avg_bytes_per_bulk",
    "Fwd Pkts/b Avg":     "fwd_avg_packets_per_bulk",
    "Fwd Blk Rate Avg":   "fwd_avg_bulk_rate",
    "Bwd Byts/b Avg":     "bwd_avg_bytes_per_bulk",
    "Bwd Pkts/b Avg":     "bwd_avg_packets_per_bulk",
    "Bwd Blk Rate Avg":   "bwd_avg_bulk_rate",
    "Subflow Fwd Pkts":   "subflow_fwd_packets",
    "Subflow Fwd Byts":   "subflow_fwd_bytes",
    "Subflow Bwd Pkts":   "subflow_bwd_packets",
    "Subflow Bwd Byts":   "subflow_bwd_bytes",
    "Init Fwd Win Byts":  "init_win_bytes_forward",
    "Init Bwd Win Byts":  "init_win_bytes_backward",
    "Fwd Act Data Pkts":  "act_data_pkt_fwd",
    "Fwd Seg Size Min":   "min_seg_size_forward",
    "Active Mean":        "active_mean",
    "Active Std":         "active_std",
    "Active Max":         "active_max",
    "Active Min":         "active_min",
    "Idle Mean":          "idle_mean",
    "Idle Std":           "idle_std",
    "Idle Max":           "idle_max",
    "Idle Min":           "idle_min",
}

# ---------------------------------------------------------------------------
# D. ATTACK LABEL MAP  (raw 2018 label strings → binary 0/1)
# ---------------------------------------------------------------------------

ATTACK_LABEL_MAP: dict[str, int] = {
    "Benign":                   0,
    "BENIGN":                   0,
    "FTP-BruteForce":           1,
    "SSH-Bruteforce":           1,
    "DoS attacks-Hulk":         1,
    "DoS attacks-SlowHTTPTest": 1,
    "DoS attacks-GoldenEye":    1,
    "DoS attacks-Slowloris":    1,
    "DDoS attacks-LOIC-HTTP":   1,
    "DDOS attack-HOIC":         1,
    "DDOS attack-LOIC-UDP":     1,
    "Brute Force -Web":         1,
    "Brute Force -XSS":         1,
    "SQL Injection":            1,
    "Infilteration":            1,
    "Bot":                      1,
    "Label":                    -1,  # stray header row — caller must filter rows where label == -1
}

# ---------------------------------------------------------------------------
# E. LABEL COLUMN NAMES & ATTACK CLASSES
# ---------------------------------------------------------------------------

BINARY_LABEL_COL     = "label"        # 0 = benign, 1 = attack
MULTICLASS_LABEL_COL = "label_class"  # integer index into ATTACK_CLASSES

ATTACK_CLASSES: list[str] = [
    "BENIGN",
    "DoS",
    "DDoS",
    "PortScan",
    "BruteForce",
    "Bot",
    "Infiltration",
    "Heartbleed",
    "WebAttack",
]

# ---------------------------------------------------------------------------
# F. MITRE ATT&CK MAPPING
# ---------------------------------------------------------------------------

MITRE_ATTACK_MAP: dict[str, dict] = {
    "BruteForce": {
        "tactic":    "Initial Access",
        "technique": "T1110",
        "name":      "Brute Force",
    },
    "Phishing": {
        "tactic":    "Initial Access",
        "technique": "T1566",
        "name":      "Phishing",
    },
    "SQLInjection": {
        "tactic":    "Execution",
        "technique": "T1190",
        "name":      "Exploit Public-Facing Application",
    },
    "XSS": {
        "tactic":    "Execution",
        "technique": "T1059.007",
        "name":      "JavaScript",
    },
    "CommandInject": {
        "tactic":    "Execution",
        "technique": "T1059",
        "name":      "Command and Scripting Interpreter",
    },
    "Bot": {
        "tactic":    "Persistence",
        "technique": "T1543",
        "name":      "Create or Modify System Process",
    },
    "Infiltration": {
        "tactic":    "Lateral Movement",
        "technique": "T1078",
        "name":      "Valid Accounts",
    },
    "PortScan": {
        "tactic":    "Discovery",
        "technique": "T1046",
        "name":      "Network Service Scanning",
    },
    "DDoS": {
        "tactic":    "Impact",
        "technique": "T1498",
        "name":      "Network Denial of Service",
    },
    "DoS": {
        "tactic":    "Impact",
        "technique": "T1499",
        "name":      "Endpoint Denial of Service",
    },
    "Heartbleed": {
        "tactic":    "Defense Evasion",
        "technique": "T1600",
        "name":      "Weaken Encryption",
    },
    "Exfiltration": {
        "tactic":    "Exfiltration",
        "technique": "T1041",
        "name":      "Exfiltration Over C2 Channel",
    },
    "ZeroDay": {
        "tactic":    "Multiple",
        "technique": "T1203",
        "name":      "Exploitation for Client Execution",
    },
}

# ---------------------------------------------------------------------------
# G. RESPONSE MATRIX
# ---------------------------------------------------------------------------

RESPONSE_MATRIX: dict[str, list[str]] = {
    "DDoS":         ["rate_limit", "ip_block", "alert_high", "log_pcap"],
    "DoS":          ["rate_limit", "ip_block", "alert_high", "log_pcap"],
    "PortScan":     ["ip_block_24h", "alert_medium", "log"],
    "BruteForce":   ["ip_block_1h", "invalidate_sessions", "alert_medium"],
    "SQLInjection": ["block_request", "alert_medium", "log_payload"],
    "XSS":          ["sanitize_input", "block_request", "alert_medium"],
    "CommandInject": ["block_request", "ip_block_1h", "alert_high", "log_payload"],
    "PathTraversal": ["block_request", "ip_block_1h", "alert_high", "log_payload"],
    "Phishing":     ["block_domain", "alert_medium", "notify_admin"],
    "Bot":          ["ip_block", "c2_domain_block", "alert_high"],
    "Infiltration": ["isolate_connection", "alert_critical", "log_pcap"],
    "Heartbleed":   ["block_tls", "alert_critical", "patch_notify"],
    "ZeroDay":      ["quarantine", "alert_critical", "capture_all", "retrain"],
    "APT":          ["isolate_full", "alert_critical", "forensics_mode"],
}

# ---------------------------------------------------------------------------
# H. SEVERITY LEVELS
# ---------------------------------------------------------------------------

SEVERITY_LEVELS: dict[str, list[str]] = {
    "CRITICAL": ["Infiltration", "ZeroDay", "Heartbleed", "APT"],
    "HIGH":     ["DDoS", "DoS", "Bot", "Ransomware", "CommandInject", "PathTraversal"],
    "MEDIUM":   ["BruteForce", "SQLInjection", "XSS"],
    "LOW":      ["PortScan", "Phishing"],
    "INFO":     ["Reconnaissance"],
}

# ---------------------------------------------------------------------------
# I. HONEYPOT SERVICES
# ---------------------------------------------------------------------------

HONEYPOT_SERVICES: list[dict] = [
    {"name": "fake_ssh",   "port": 2222, "protocol": "TCP"},
    {"name": "fake_ftp",   "port": 2121, "protocol": "TCP"},
    {"name": "fake_admin", "port": 8080, "path": "/admin"},
    {"name": "fake_db",    "port": 5432, "protocol": "TCP"},
    {"name": "fake_api",   "port": 9000, "path": "/api/v1/users"},
]

# ---------------------------------------------------------------------------
# J. THREAT INTELLIGENCE FEEDS
# ---------------------------------------------------------------------------

THREAT_FEEDS: dict[str, dict] = {
    "abuseipdb": {
        "url":     "https://api.abuseipdb.com/api/v2/check",
        "key_env": "ABUSEIPDB_API_KEY",
        "free":    True,
        "purpose": "IP reputation score 0-100",
    },
    "virustotal": {
        "url":     "https://www.virustotal.com/vtapi/v2/url/report",
        "key_env": "VIRUSTOTAL_API_KEY",
        "free":    True,
        "purpose": "URL and file hash reputation",
    },
    "tor_exit_nodes": {
        "url":     "https://check.torproject.org/exit-addresses",
        "key_env": None,
        "free":    True,
        "purpose": "Tor exit node detection",
    },
    "local_blacklist": {
        "path":    str(THREAT_DIR / "ip_blacklist.txt"),
        "update":  "daily",
        "purpose": "Known malicious IPs",
    },
}

# ---------------------------------------------------------------------------
# K. ENGINEERED FEATURES  (lightweight 10-feature IDS)
# ---------------------------------------------------------------------------

ENGINEERED_FEATURES: list[str] = [
    "bwd_packet_length_std",
    "average_packet_size",
    "packet_length_mean",
    "packet_length_std",
    "max_packet_length",
    "bytes_per_pkt",
    "psh_flag_count",
    "destination_port",
    "urg_flag_count",
    "bwd_packet_length_mean",
]

# ---------------------------------------------------------------------------
# L. NUMERIC CONSTANTS
# ---------------------------------------------------------------------------

CHUNK_SIZE                 = 100_000   # max rows per CSV chunk
K_BEST_FEATURES            = 30        # ANOVA feature selector k
SCALE_POS_WEIGHT           = 3.0       # XGBoost class imbalance weight
CONFIDENCE_THRESHOLD       = 0.55      # in-distribution detection threshold
CONFIDENCE_THRESHOLD_CROSS = 0.35      # cross-dataset detection threshold
MAX_RAM_GB                 = 8         # memory ceiling for chunk sizing
ADAPTIVE_MISTAKE_THRESHOLD = 1_000     # FP/FN count before adaptive retrain
ADAPTIVE_MAX_SAMPLES       = 50_000    # max mistake samples kept for retrain
REALTIME_CHUNK_SIZE        = 5_000     # live flow batch size
LOG_INTERVAL               = 10_000    # rows between progress log messages
SHAP_BACKGROUND_SAMPLES    = 500       # KernelExplainer background set size
SHAP_EXPLAIN_SAMPLES       = 200       # samples to explain per run

# ---------------------------------------------------------------------------
# M. LIVE CAPTURE & FLOW ASSEMBLY  (core/flow_collector.py, sentinel.py live)
# ---------------------------------------------------------------------------

LIVE_INTERFACE_DEFAULT = "eth0"              # overridden by --interface
LIVE_BPF_FILTER        = "tcp or udp"        # overridden by --bpf-filter
FLOW_ACTIVE_TIMEOUT_S  = 5.0                 # gap (s) that starts a new active period
FLOW_IDLE_TIMEOUT_S    = 120.0               # gap (s) after which an open flow is force-closed
FLOW_GC_INTERVAL_S     = 2.0                 # how often live mode drains completed/idle flows
FLOW_MAX_OPEN          = 50_000              # safety cap on concurrently open flows
LAB_HOST_ONLY_SUBNET   = "192.168.56.0/24"   # reference only — see lab/README.md

# ---------------------------------------------------------------------------
# SIGNATURE PATTERNS  (Layer 2 detection)
# ---------------------------------------------------------------------------

SQL_INJECTION_PATTERNS: list[str] = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    # Bare ";"/"%3B" deliberately excluded from this alternation: a
    # semicolon after "param=" is exactly as consistent with shell command
    # chaining as with SQL statement stacking (confirmed live -- a pure
    # CommandInject test payload, "q=; wget ...", matched this pattern
    # before ever reaching the command-injection check, since SQL patterns
    # are checked first). Quote/comment markers are genuinely SQL-specific
    # and stay; stacked-query detection without those still works via the
    # keyword-anchored ";\s*(DROP|DELETE|UPDATE|INSERT)" pattern in
    # detection/layer2_signatures.py's _EXTRA_SQL_PATTERNS.
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-))",
    r"UNION.+SELECT",
    r"INSERT\s+INTO",
    r"DROP\s+TABLE",
    r"exec(\s|\+)+(s|x)p\w+",
]

XSS_PATTERNS: list[str] = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    # Word-boundary anchored: unanchored "on\w+\s*=" matches "on" as a
    # substring anywhere, not just at the start of an event-handler
    # attribute -- confirmed live, matching "sessionid=" (contains
    # "...ONid=") in an ordinary Cookie header.
    r"\bon\w+\s*=",
    r"<iframe",
    r"document\.cookie",
    r"eval\(",
]

COMMAND_INJECTION_PATTERNS: list[str] = [
    # A bare single "&" matches every ordinary URL-encoded form POST body
    # (key1=val1&key2=val2) -- confirmed as a live false-positive source
    # once Layer 2 was actually wired into the pipeline (2026-07-28):
    # relabelled every hydra brute-force credential POST as CommandInject.
    # A bare ";" is just as bad: standard browser User-Agent syntax
    # ("Mozilla/5.0 (X11; Linux x86_64)...") always contains one -- also
    # confirmed live, via slowhttptest's default User-Agent, relabelling
    # an entire Slowloris-style DoS test as CommandInject. Pipe/backtick/
    # doubled-"&" stay bare (not observed in ordinary HTTP header syntax);
    # ";" now requires a recognisable shell command right after it, which
    # real chaining has and "; Linux x86_64" or "; q=0.9" do not.
    r"[|`]|&&",
    r";\s*(ls|cat|whoami|id|pwd|uname|wget|curl|nc|bash|sh|python[23]?|perl|rm|chmod|kill|ping|ifconfig|netstat|ps)\b",
    r"\$\(.*\)",
    r"wget\s+http",
    r"curl\s+http",
    r"/bin/(bash|sh|cmd)",
]

# ---------------------------------------------------------------------------
# ENCRYPTED TRAFFIC FEATURES  (Layer 3 TLS analysis)
# ---------------------------------------------------------------------------

ENCRYPTED_TRAFFIC_FEATURES: list[str] = [
    "tls_handshake_duration",
    "certificate_validity_days",
    "cipher_suite_strength",
    "packet_size_variance",
    "connection_frequency",
    "ja3_fingerprint",
    "ja3s_fingerprint",
    "byte_distribution_entropy",
]

# ---------------------------------------------------------------------------
# DATASET METADATA
# ---------------------------------------------------------------------------

CIC_IDS_2017_COLS           = 82
CIC_IDS_2018_COLS           = 80
# Indices of zero-variance (constant) columns in 2017 dataset — drop before fit
CONSTANT_FEATURE_INDICES    = [31, 33, 56, 57, 58, 59, 60, 61]
