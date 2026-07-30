"""
lab/verify_binary_payload_guard.py

Purpose: Self-check for the Layer 2 binary-payload false-positive fix
         (2026-07-31). Confirmed live: an nmap -sU ISAKMP probe (UDP/500)
         got flagged attack=CommandInject, HIGH severity, and genuinely
         blocked -- its structured binary header coincidentally contained
         a 0x7C byte, matching COMMAND_INJECTION_PATTERNS' "[|`]" pattern.
         sentinel.py._run_signatures() now skips any payload_sample
         containing the utf-8 replacement character (U+FFFD), since that
         means the raw bytes weren't valid text to begin with -- real HTTP
         payloads always are. Confirms two things: the exact ISAKMP bytes
         that caused the false positive are now skipped, and a genuine
         CommandInject payload still gets caught.

Usage:
    python lab/verify_binary_payload_guard.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd

from sentinel import SentinelIPS

# The exact 40-byte ISAKMP payload captured live 2026-07-30 that produced
# the false CommandInject match (contains 0x7C at byte 17).
ISAKMP_PAYLOAD_BYTES = bytes.fromhex(
    "72fe1d130000000000000002000186a00001977c0000000000000000000000000000000000000000"
)
ISAKMP_PAYLOAD = ISAKMP_PAYLOAD_BYTES.decode("utf-8", errors="replace")

REAL_COMMAND_INJECT_PAYLOAD = (
    "GET /search?q=;cat%20/etc/passwd HTTP/1.1\r\nHost: 192.168.56.1\r\n\r\n"
)


def run_signatures(payload: str) -> pd.DataFrame:
    ips = SentinelIPS()  # no model_path needed -- _run_signatures never touches layer1
    chunk = pd.DataFrame({
        "payload_sample": [payload],
        "dst_ip": ["192.168.56.1"],
    })
    return ips._run_signatures(chunk)


print("--- Check 1: ISAKMP binary payload no longer flagged CommandInject ---")
assert "�" in ISAKMP_PAYLOAD, "sanity check: payload should contain U+FFFD"
result = run_signatures(ISAKMP_PAYLOAD)
sig_type = result.get("sig_attack_type", pd.Series([None])).iloc[0]
assert sig_type is None or pd.isna(sig_type), (
    f"FAIL: binary ISAKMP payload still matched as {sig_type!r}"
)
print("PASS: binary payload correctly skipped, no false CommandInject")

print()
print("--- Check 2: a real CommandInject payload is still caught ---")
result = run_signatures(REAL_COMMAND_INJECT_PAYLOAD)
sig_type = result.get("sig_attack_type", pd.Series([None])).iloc[0]
assert sig_type == "CommandInject", f"FAIL: expected CommandInject, got {sig_type!r}"
print("PASS: real CommandInject payload still detected correctly")

print()
print("All checks passed.")
