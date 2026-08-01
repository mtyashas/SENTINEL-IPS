"""
lab/verify_connection_terminator_guard.py

Purpose: Self-check for the PowerShell-injection guard added to
         ConnectionTerminator.terminate_ip() (2026-08-01, closing the
         finding in docs/SECURITY_TODO.md). _terminate_windows()
         interpolates ip unescaped into a PowerShell -Command string; a
         value containing a quote could break out and run arbitrary
         PowerShell. terminate_ip() now validates with
         ipaddress.ip_address() first and refuses anything that doesn't
         parse, before any PowerShell string gets built.

Usage:
    python lab/verify_connection_terminator_guard.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from response.connection_terminator import ConnectionTerminator

ct = ConnectionTerminator(enforce_network=False)

print("--- Check 1: injection-shaped IP is refused, never reaches PowerShell ---")
malicious = "1.2.3.4'; Start-Process calc; '"
result = ct.terminate_ip(malicious)
assert not result.success, f"FAIL: malicious IP was not rejected: {result}"
assert result.method == "invalid_ip", f"FAIL: expected method=invalid_ip, got {result.method!r}"
print(f"PASS: {malicious!r} refused (method={result.method})")

print()
print("--- Check 2: a genuine IP still proceeds normally ---")
result2 = ct.terminate_ip("192.168.56.10")
assert result2.success, f"FAIL: valid IP was rejected: {result2}"
print(f"PASS: valid IP proceeds (method={result2.method})")

print()
print("--- Check 3: IPv6 addresses also pass validation ---")
result3 = ct.terminate_ip("2001:db8::1")
assert result3.success, f"FAIL: valid IPv6 was rejected: {result3}"
print("PASS: valid IPv6 proceeds")

print()
print("All checks passed.")
