"""
lab/verify_webshell_detection.py

Purpose: Self-check for WebShell detection (2026-07-31, backlog item added
         2026-07-30 when it was found neither WebShell nor CSRF had any
         detector at all -- config.py's ATTACK_CLASSES/MITRE_ATTACK_MAP/
         RESPONSE_MATRIX/SEVERITY_LEVELS and detection/layer2_signatures.py
         had zero entries for either). Confirms a PHP-eval-style web-shell
         payload uploaded to lab/target_service.py's new /upload endpoint
         gets caught by Layer 2, promoted to pred_binary=1, floored at
         confidence 0.90, and correctly labelled WebShell/CRITICAL end to
         end through the real SentinelIPS pipeline -- not just the
         standalone SignatureDetector.

Usage:
    python lab/verify_webshell_detection.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd

from detection.layer2_signatures import SignatureDetector
from sentinel import SentinelIPS

# Test fixture only: a PHP string literal used as attacker-shaped input to
# the detector below. Never parsed or executed as PHP/Python anywhere.
WEBSHELL_PAYLOAD = (
    "POST /upload HTTP/1.1\r\nHost: 192.168.56.1\r\n\r\n"
    "<?php eval($_POST['cmd']); ?>"
)
BENIGN_UPLOAD_PAYLOAD = (
    "POST /upload HTTP/1.1\r\nHost: 192.168.56.1\r\n\r\n"
    "just a normal text file, nothing suspicious here"
)


print("--- Check 1: standalone SignatureDetector catches the PHP eval-shell pattern ---")
sig = SignatureDetector()
hit = sig.check_payload(WEBSHELL_PAYLOAD)
assert hit["detected"], f"FAIL: web shell payload not detected: {hit}"
assert hit["attack_type"] == "WebShell", f"FAIL: expected WebShell, got {hit['attack_type']!r}"
assert hit["severity"] == "CRITICAL", f"FAIL: expected CRITICAL, got {hit['severity']!r}"
assert hit["mitre_technique"] == "T1505.003"
print(f"PASS: {hit['attack_type']} / {hit['severity']} / {hit['mitre_technique']} "
      f"(pattern: {hit['pattern_matched']})")

print()
print("--- Check 2: a normal file upload is NOT flagged ---")
hit = sig.check_payload(BENIGN_UPLOAD_PAYLOAD)
assert not hit["detected"], f"FAIL: benign upload incorrectly flagged: {hit}"
print("PASS: benign upload correctly ignored")

print()
print("--- Check 3: end-to-end through SentinelIPS._run_signatures() ---")
ips = SentinelIPS()  # no model_path needed -- _run_signatures never touches layer1
chunk = pd.DataFrame({
    "payload_sample": [WEBSHELL_PAYLOAD],
    "dst_ip": ["192.168.56.1"],
})
result = ips._run_signatures(chunk)
assert result.iloc[0]["sig_attack_type"] == "WebShell"
assert result.iloc[0]["pred_binary"] == 1, "signature hit must promote pred_binary to 1"
assert result.iloc[0]["confidence"] >= 0.90, "signature hit must floor confidence at 0.90"
print(f"PASS: sig_attack_type=WebShell pred_binary=1 confidence={result.iloc[0]['confidence']:.2f}")

print()
print("All checks passed.")
