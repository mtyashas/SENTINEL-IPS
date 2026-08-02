"""
lab/verify_reenforce_on_known_ip.py

Purpose: Self-check for the "stale memory-only block never gets a real
         firewall rule" bug found during the 2026-08-02 --enforce-blocks
         live-fire test. IPBlacklister.block() used to return early on
         "already in self._entries" with no way to tell whether an OS
         firewall rule had ever actually been applied for that IP -- so an
         IP first seen while enforce_os_firewall=False (the default for
         every lab session before tonight) would stay memory-only forever,
         even after SENTINEL restarted with --enforce-blocks. This is
         exactly what happened live: 192.168.56.10 was already in
         threat_intel/ip_blacklist.txt from prior detect-and-log runs, so
         the PortScan block during the enforce-blocks test silently never
         called netsh. Fixed via a new _BlockEntry.fw_applied flag.

Usage:
    python lab/verify_reenforce_on_known_ip.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from response.ip_blacklister import IPBlacklister

fw_calls = []


def fake_apply_fw_block(self, ip):
    if not self._enforce_fw:
        return True, "noop"
    fw_calls.append(ip)
    return True, "fake_fw"


IPBlacklister._apply_fw_block = fake_apply_fw_block

print("--- Check 1: block while enforcement is OFF stays memory-only ---")
bl = IPBlacklister(enforce_os_firewall=False)
r1 = bl.block("203.0.113.10", duration_s=3600, reason="test")
assert r1.method == "noop", f"FAIL: expected noop, got {r1.method!r}"
assert fw_calls == [], f"FAIL: firewall was called while enforcement off: {fw_calls}"
assert not bl._entries["203.0.113.10"].fw_applied, "FAIL: fw_applied should stay False"
print("PASS: no firewall call, fw_applied stays False")

print()
print("--- Check 2: same IP, same process, enforcement now ON -> real block fires ---")
bl._enforce_fw = True  # simulates restarting sentinel.py live --enforce-blocks
r2 = bl.block("203.0.113.10", duration_s=3600, reason="test-reenforce")
assert r2.method == "fake_fw", f"FAIL: expected firewall to actually be applied, got {r2.method!r}"
assert fw_calls == ["203.0.113.10"], f"FAIL: firewall call missing: {fw_calls}"
assert bl._entries["203.0.113.10"].fw_applied, "FAIL: fw_applied should now be True"
print("PASS: stale memory-only block got a real firewall rule on re-block")

print()
print("--- Check 3: blocking again after that is a true no-op (no duplicate rule) ---")
fw_calls.clear()
r3 = bl.block("203.0.113.10", duration_s=3600, reason="test-again")
assert r3.method == "memory_already_blocked", f"FAIL: expected memory_already_blocked, got {r3.method!r}"
assert fw_calls == [], f"FAIL: firewall was called again unnecessarily: {fw_calls}"
print("PASS: already-enforced IP does not re-trigger the firewall")

print()
print("--- Check 4: a brand-new IP under enforcement applies the firewall immediately ---")
fw_calls.clear()
bl2 = IPBlacklister(enforce_os_firewall=True)
r4 = bl2.block("203.0.113.20", duration_s=3600, reason="test-fresh")
assert r4.method == "fake_fw", f"FAIL: expected fake_fw, got {r4.method!r}"
assert fw_calls == ["203.0.113.20"]
print("PASS: fresh IP under enforcement blocks normally (no regression)")

print()
print("All checks passed.")
