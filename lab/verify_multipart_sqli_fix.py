"""
lab/verify_multipart_sqli_fix.py

Purpose: Regression check for a real false-positive found live 2026-08-25
         while testing the new Exfiltration detector: ANY multipart/
         form-data file upload got mislabelled SQLInjection. Two
         independent collisions, found one after the other via live
         re-testing (the second only surfaced after fixing the first):

         1. SQL_INJECTION_PATTERNS' first entry had a bare (\\-\\-)
            alternative that matches a multipart boundary marker line's
            leading "--" in the request body.
         2. The second entry's "param=...--" shape ALSO matched one level
            up, in the request HEADERS: curl declares the boundary as
            "Content-Type: ...; boundary=------<random>", and curl's
            "Expect: 100-continue" behavior means this header-only text is
            *all* that's in the first captured packet -- payload_sample is
            always just the first data-carrying packet, so the actual
            random file bytes (in a later packet) are never even seen by
            this check for a curl upload.

         Confirmed both live against real captured PCAP data (extracted
         and replayed the actual first packet of brindha's real /upload
         POST), not just synthetic guesses.

         Same class of bug already fixed twice before in this exact file
         for the exact same reason (see config.py's SQL_INJECTION_PATTERNS/
         COMMAND_INJECTION_PATTERNS comments: bare ";"/"&" previously
         removed after confirmed collisions with ordinary form-POST bodies
         and User-Agent strings) -- these fixes follow that same
         established pattern rather than introducing a new mechanism.

         Confirms: (1) the real captured multipart upload header text (the
         actual bytes from the PCAP, not a guess) no longer matches either
         SQL pattern, (2) genuine SQLi payloads -- quote-based, UNION-based,
         AND bare numeric-context comment injection with no quote at all
         (e.g. "id=5--") -- all still match correctly. The numeric case
         specifically guards against a blanket "--" removal from the
         second pattern, which would have silently lost that real
         technique instead of just excluding the boundary-token collision.

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

MULTIPART_BODY_PREAMBLE = (
    "------------------------acbd1234567890\r\n"
    "Content-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\n"
    "Content-Type: application/octet-stream\r\n\r\n"
)

# The actual first packet of a real curl multipart upload -- extracted
# directly from a live PCAP capture (sentinel_20260824_184225_c811178b.pcap),
# not a guess. curl's "Expect: 100-continue" means this header-only text is
# genuinely all that payload_sample ever sees for this connection.
REAL_CURL_UPLOAD_HEADERS = (
    "POST /upload HTTP/1.1\r\n"
    "Host: 192.168.0.104\r\n"
    "User-Agent: curl/8.20.0\r\n"
    "Accept: */*\r\n"
    "Content-Length: 6291667\r\n"
    "Content-Type: multipart/form-data; "
    "boundary=------------------------ICe14lY3ZsHYVuiPeTERqD\r\n"
    "Expect: 100-continue\r\n\r\n"
)

print("--- Check 1: a multipart boundary marker line (body) is NOT flagged SQLInjection ---")
result = sig.check_payload(MULTIPART_BODY_PREAMBLE)
assert not result["detected"], \
    f"FAIL: ordinary multipart boundary/headers incorrectly flagged: {result}"
print("PASS: multipart boundary/headers correctly NOT flagged")

print()
print("--- Check 2: the real captured curl upload headers (boundary=------...) are NOT flagged ---")
result_real = sig.check_payload(REAL_CURL_UPLOAD_HEADERS)
assert not result_real["detected"], \
    f"FAIL: real captured curl upload headers incorrectly flagged: {result_real}"
print("PASS: real captured curl upload headers correctly NOT flagged")

print()
print("--- Check 3: a real quote-based SQLi payload is still caught ---")
result2 = sig.check_payload("' UNION SELECT NULL--")
assert result2["detected"] and result2["attack_type"] == "SQLInjection", \
    f"FAIL: real SQLi payload no longer detected: {result2}"
print(f"PASS: '\\' UNION SELECT NULL--' still correctly flagged SQLInjection")

print()
print("--- Check 4: a real assignment-based SQLi payload (quoted) is still caught ---")
result3 = sig.check_payload("id=1' OR '1'='1' --")
assert result3["detected"] and result3["attack_type"] == "SQLInjection", \
    f"FAIL: real SQLi payload no longer detected: {result3}"
print(f"PASS: \"id=1' OR '1'='1' --\" still correctly flagged SQLInjection")

print()
print("--- Check 5: bare numeric-context comment SQLi (no quote at all) is still caught ---")
result4 = sig.check_payload("id=5--")
assert result4["detected"] and result4["attack_type"] == "SQLInjection", \
    f"FAIL: numeric-context comment SQLi no longer detected -- the fix over-corrected: {result4}"
result5 = sig.check_payload("id=5--\r\nHost: example.com\r\n")
assert result5["detected"] and result5["attack_type"] == "SQLInjection", \
    f"FAIL: numeric-context comment SQLi followed by more request text no longer detected: {result5}"
print("PASS: \"id=5--\" (no quote, numeric SQLi) still correctly flagged, "
      "both at end-of-string and followed by more text")

print()
print("All checks passed.")
