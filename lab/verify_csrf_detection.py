"""
lab/verify_csrf_detection.py

Purpose: Self-check for CSRF detection (2026-07-31, backlog item added
         2026-07-30 alongside WebShell). CSRF is structurally different
         from every other attack type this project detects: the request
         that reaches the server comes from the *victim's own browser*,
         not the attacker's machine, so the standard IP-blacklist response
         every other attack type uses would block the victim, not the
         attacker. This confirms three things end to end through the real
         SentinelIPS pipeline: (1) a forged cross-site request against
         lab/target_service.py's /account/email is detected and the
         session token extracted, (2) a legitimate same-origin request to
         the same endpoint is NOT flagged, and (3) most importantly --
         _run_response() invalidates the session via ConnectionTerminator
         and never calls IPBlacklister.block() for this attack type.

Usage:
    python lab/verify_csrf_detection.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from detection.layer2_signatures import SignatureDetector
from sentinel import SentinelIPS

VICTIM_IP = "192.168.56.20"   # the request's real src_ip -- the *victim*
SESSION_TOKEN = "abc123victimtoken"

FORGED_REQUEST = (
    "POST /account/email HTTP/1.1\r\n"
    "Host: 192.168.56.1\r\n"
    f"Cookie: session={SESSION_TOKEN}\r\n"
    "Origin: http://attacker-controlled.example\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
    "email=attacker@evil.example"
)
LEGITIMATE_REQUEST = (
    "POST /account/email HTTP/1.1\r\n"
    "Host: 192.168.56.1\r\n"
    f"Cookie: session={SESSION_TOKEN}\r\n"
    "Origin: http://192.168.56.1\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
    "email=me@example.com"
)
NO_SESSION_REQUEST = (
    "POST /account/email HTTP/1.1\r\n"
    "Host: 192.168.56.1\r\n"
    "Origin: http://attacker-controlled.example\r\n\r\n"
    "email=nobody@example.com"
)


print("--- Check 1: forged cross-site request detected, session token extracted ---")
sig = SignatureDetector()
hit = sig.check_csrf(FORGED_REQUEST)
assert hit["detected"], f"FAIL: forged request not detected: {hit}"
assert hit["attack_type"] == "CSRF"
assert hit["session_token"] == SESSION_TOKEN, (
    f"FAIL: expected token {SESSION_TOKEN!r}, got {hit.get('session_token')!r}"
)
print(f"PASS: CSRF detected, session_token={hit['session_token']!r}")

print()
print("--- Check 2: legitimate same-origin request NOT flagged ---")
hit = sig.check_csrf(LEGITIMATE_REQUEST)
assert not hit["detected"], f"FAIL: legitimate same-origin request incorrectly flagged: {hit}"
print("PASS: same-origin request correctly ignored")

print()
print("--- Check 3: request with no session cookie NOT flagged (nothing to forge) ---")
hit = sig.check_csrf(NO_SESSION_REQUEST)
assert not hit["detected"], f"FAIL: sessionless request incorrectly flagged: {hit}"
print("PASS: sessionless request correctly ignored")

print()
print("--- Check 4: end-to-end -- session invalidated, victim IP NEVER blocked ---")
import pandas as pd

ips = SentinelIPS()  # no model_path needed -- this path never touches layer1

row = {
    "sig_attack_type":    "CSRF",
    "src_ip":             VICTIM_IP,
    "dst_ip":             "192.168.56.1",
    "csrf_session_token": SESSION_TOKEN,
    "confidence":         0.90,
}
event = ips._build_event(pd.Series(row))
assert event["attack_type"] == "CSRF"
assert event["session_token"] == SESSION_TOKEN

assert not ips._terminator.is_session_revoked(SESSION_TOKEN), "token should start valid"
ips._run_response(event)

assert ips._terminator.is_session_revoked(SESSION_TOKEN), (
    "FAIL: session was not invalidated after a CSRF detection"
)
print(f"PASS: session {SESSION_TOKEN!r} invalidated via ConnectionTerminator")

assert not ips._blacklist.is_blocked(VICTIM_IP), (
    f"FAIL: victim IP {VICTIM_IP} was blocked -- CSRF must never block src_ip"
)
print(f"PASS: victim IP {VICTIM_IP} was NOT blocked (this is the whole point)")

print()
print("All checks passed.")
