"""
lab/verify_multipart_sqli_fix.py

Purpose: Regression check for a real false-positive found live 2026-08-25
         while testing the new Exfiltration detector: ANY multipart/
         form-data file upload got mislabelled SQLInjection, because
         SQL_INJECTION_PATTERNS had two independent bare, context-free
         sub-patterns that ordinary MIME multipart syntax trivially
         satisfies -- (\\-\\-) matches a boundary line's leading "--", and
         the second pattern's "=...;" shape matches a Content-Disposition
         header's own "name=\"file\"; filename=..." parameter syntax.
         Confirmed live: brindha's 6MB /upload POST (pure random bytes,
         nothing SQLi-shaped at all) was flagged SQLInjection before the
         new Exfiltration check ever got a chance to see the flow.

         Same class of bug already fixed twice before in this exact file
         for the exact same reason (see config.py's SQL_INJECTION_PATTERNS/
         COMMAND_INJECTION_PATTERNS comments: bare ";"/"&" previously
         removed after confirmed collisions with ordinary form-POST bodies
         and User-Agent strings) -- this fix follows that same established
         pattern rather than introducing a new mechanism.

         Confirms: (1) a real multipart/form-data upload's boundary +
         headers no longer match either SQL pattern, (2) genuine SQLi
         payloads (quote-based and UNION-based) still match correctly --
         the fix must not weaken real detection, only remove the two
         confirmed collision points.

Usage:
    python lab/verify_multipart_sqli_fix.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from detection.layer2_signatures import SignatureDetector

sig = SignatureDetector()

MULTIPART_PREAMBLE = (
    "------------------------acbd1234567890\r\n"
    "Content-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\n"
    "Content-Type: application/octet-stream\r\n\r\n"
)

print("--- Check 1: a real multipart upload's boundary/headers are NOT flagged SQLInjection ---")
result = sig.check_payload(MULTIPART_PREAMBLE)
assert not result["detected"], \
    f"FAIL: ordinary multipart boundary/headers incorrectly flagged: {result}"
print("PASS: multipart boundary/headers correctly NOT flagged")

print()
print("--- Check 2: a real quote-based SQLi payload is still caught ---")
result2 = sig.check_payload("' UNION SELECT NULL--")
assert result2["detected"] and result2["attack_type"] == "SQLInjection", \
    f"FAIL: real SQLi payload no longer detected: {result2}"
print(f"PASS: '\\' UNION SELECT NULL--' still correctly flagged SQLInjection")

print()
print("--- Check 3: a real assignment-based SQLi payload is still caught ---")
result3 = sig.check_payload("id=1' OR '1'='1' --")
assert result3["detected"] and result3["attack_type"] == "SQLInjection", \
    f"FAIL: real SQLi payload no longer detected: {result3}"
print(f"PASS: \"id=1' OR '1'='1' --\" still correctly flagged SQLInjection")

print()
print("All checks passed.")
