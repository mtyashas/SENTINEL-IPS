"""
lab/verify_session_hijack.py

Purpose: Self-check for Session Hijacking detection (2026-08-24).
         detection.layer2_signatures.SignatureDetector.check_session_hijack()
         tracks which source IP a session cookie was last seen from --
         reusing check_csrf()'s existing cookie-extraction logic rather
         than duplicating it. Confirms: (1) the same session cookie from
         the same IP twice in a row is never flagged (normal repeat
         traffic), (2) the same session cookie appearing from a NEW IP is
         flagged, and the response carries the session_token needed for
         invalidation, (3) a request with no session cookie at all is a
         clean no-op, (4) the bounded history evicts its oldest entry once
         _SESSION_HISTORY_MAX_ENTRIES is exceeded, so this can't grow
         unbounded on a long-running server.

Usage:
    python lab/verify_session_hijack.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from detection.layer2_signatures import SignatureDetector

def make_request(session_id: str) -> str:
    return (
        f"GET /dashboard HTTP/1.1\r\n"
        f"Host: 192.168.0.104\r\n"
        f"Cookie: session={session_id}\r\n"
        f"\r\n"
    )

print("--- Check 1: same session cookie, same IP, twice -- never flagged ---")
sig = SignatureDetector()
req = make_request("abc123")
first = sig.check_session_hijack(req, "192.168.0.10")
second = sig.check_session_hijack(req, "192.168.0.10")
assert not first["detected"], f"FAIL: first sighting of a session should never be flagged: {first}"
assert not second["detected"], f"FAIL: same IP repeating should not be flagged: {second}"
print("PASS: first sighting and same-IP repeat both correctly NOT flagged")

print()
print("--- Check 2: same session cookie, different IP -- flagged, carries session_token ---")
hijack = sig.check_session_hijack(req, "203.0.113.99")
assert hijack["detected"], f"FAIL: session cookie switching IPs should be flagged: {hijack}"
assert hijack["attack_type"] == "Session Hijacking"
assert hijack["session_token"] == "abc123"
print(f"PASS: IP switch on an existing session correctly flagged -> session_token={hijack['session_token']!r}")

print()
print("--- Check 2b: the SAME new IP repeating right after is not re-flagged (only the transition fires) ---")
repeat = sig.check_session_hijack(req, "203.0.113.99")
assert not repeat["detected"], f"FAIL: the new IP's own follow-up requests should not re-trigger: {repeat}"
print("PASS: only the transition moment was flagged, not every subsequent request from the new IP")

print()
print("--- Check 3: request with no session cookie is a clean no-op ---")
no_cookie_req = "GET /health HTTP/1.1\r\nHost: 192.168.0.104\r\n\r\n"
result3 = sig.check_session_hijack(no_cookie_req, "192.168.0.10")
assert not result3["detected"]
print("PASS: request with no session cookie correctly NOT flagged")

print()
print("--- Check 4: bounded history evicts the oldest entry past _SESSION_HISTORY_MAX_ENTRIES ---")
from detection.layer2_signatures import _SESSION_HISTORY_MAX_ENTRIES
sig2 = SignatureDetector()
sig2.check_session_hijack(make_request("first-session"), "10.0.0.1")
for i in range(_SESSION_HISTORY_MAX_ENTRIES):
    sig2.check_session_hijack(make_request(f"filler-{i}"), "10.0.0.2")
assert "first-session" not in sig2._session_last_ip, \
    "FAIL: oldest entry should have been evicted once the history exceeded its cap"
assert len(sig2._session_last_ip) <= _SESSION_HISTORY_MAX_ENTRIES
print(f"PASS: history correctly bounded at {_SESSION_HISTORY_MAX_ENTRIES} entries, oldest evicted")

print()
print("All checks passed.")
