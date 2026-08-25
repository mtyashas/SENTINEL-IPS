"""
lab/verify_ddos_correlation.py

Purpose: Self-check for DDoS multi-source correlation (2026-08-25).
         Confirmed live earlier tonight: two simultaneous hping3 floods
         against the same target each got labeled DoS independently --
         correct per-source, but not the actual definition of a
         *distributed* denial of service (multiple sources flooding one
         target). connection_rate() already flags each (src, dst) pair
         independently; this adds cross-source correlation on top: how
         many DISTINCT sources are concurrently flood-flagged against the
         same destination.

         Confirms: (1) a single flooding source against a destination is
         NOT correlated as DDoS (still just DoS), (2) two DISTINCT sources
         flooding the same destination concurrently ARE correlated as
         DDoS, (3) a source whose flood happened outside the concurrent
         window no longer counts, (4) sentinel.py's _run_dos() upgrades
         the label from DoS to DDoS when the correlation says so, and
         leaves single-source floods labeled DoS.

Usage:
    python lab/verify_ddos_correlation.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scapy.layers.inet import IP, TCP

from core.flow_collector import FlowCollector

DST = "192.168.0.104"
SRC_A, SRC_B, SRC_C = "192.168.0.150", "192.168.0.151", "10.0.0.99"


def make_flood(collector: FlowCollector, src: str, dst: str, base_ts: float, n: int = 5) -> None:
    """n connections at 0.05s apart, all to the same dst_port -- flood-shaped
    per connection_rate()'s own rate + port-concentration requirements."""
    for i in range(n):
        ts = base_ts + i * 0.05
        syn = IP(src=src, dst=dst) / TCP(sport=40000 + i, dport=80, flags="S", seq=1000)
        syn.time = ts
        collector.ingest_packet(syn)


print("--- Check 1: a single flooding source is NOT correlated as DDoS ---")
collector = FlowCollector()
base = 1_000_000.0
make_flood(collector, SRC_A, DST, base)
assert collector.connection_rate(SRC_A, DST)["is_flood"], "setup failed: SRC_A should be flood-flagged"
result = collector.ddos_correlation(DST)
assert result["distinct_flood_sources"] == 1, f"FAIL: expected 1 source, got {result}"
assert not result["is_ddos"], f"FAIL: a single flooding source should not be DDoS: {result}"
print(f"PASS: single source correctly NOT correlated as DDoS ({result})")

print()
print("--- Check 2: two distinct sources flooding the same destination concurrently ARE correlated ---")
make_flood(collector, SRC_B, DST, base + 0.5)
assert collector.connection_rate(SRC_B, DST)["is_flood"], "setup failed: SRC_B should be flood-flagged"
result2 = collector.ddos_correlation(DST)
assert result2["distinct_flood_sources"] == 2, f"FAIL: expected 2 sources, got {result2}"
assert result2["is_ddos"], f"FAIL: two concurrent flooding sources should be DDoS: {result2}"
print(f"PASS: two concurrent sources correctly correlated as DDoS ({result2})")

print()
print("--- Check 3: an old flood ages out once a new single source floods much later ---")
# Recency is measured against the most recent recorded flood, not
# wall-clock "now" (see Check 3b) -- so aging-out is tested by giving the
# dict a genuinely NEW latest entry, not by querying further into a void
# where nothing new happened.
make_flood(collector, SRC_C, DST, base + 500.0)
assert collector.connection_rate(SRC_C, DST)["is_flood"], "setup failed: SRC_C should be flood-flagged"
result3 = collector.ddos_correlation(DST)
assert result3["distinct_flood_sources"] == 1, \
    f"FAIL: SRC_A/SRC_B's old floods should have aged out relative to SRC_C's fresh one: {result3}"
assert not result3["is_ddos"], f"FAIL: only one source is current now, should not be DDoS: {result3}"
print(f"PASS: old floods correctly aged out once a new single source's flood became the latest ({result3})")

print()
print("--- Check 3b: correlation still holds under processing backlog (real bug found live 2026-08-25) ---")
# Confirmed live during demo dry-run: two genuinely-overlapping floods (both
# captured within the same second) got labeled DoS only, never DDoS, twice
# in a row -- even with tight room-coordinated timing. Root cause: under a
# heavy flood, open_flows backlogs into the tens of thousands (same
# phenomenon documented 2026-08-24), so by the time a chunk is actually
# processed, wall-clock time.time() is minutes past the packets' real
# capture time. The old ddos_correlation() compared each source's flood
# timestamp against time.time() ("now"), so a backlogged chunk always saw
# both floods as stale relative to processing time, even though they were
# genuinely concurrent at capture time.
collector3 = FlowCollector()
backlog_base = 2_000_000.0
make_flood(collector3, SRC_A, DST, backlog_base)
assert collector3.connection_rate(SRC_A, DST)["is_flood"], "setup failed: SRC_A should be flood-flagged"
make_flood(collector3, SRC_B, DST, backlog_base + 0.5)
assert collector3.connection_rate(SRC_B, DST)["is_flood"], "setup failed: SRC_B should be flood-flagged"
# Processing happens well after capture -- simulates a real backlog, not
# the instant-processing assumption Checks 1-3 exercise. No "now" override
# needed or possible any more: the fix removed wall-clock comparison
# entirely, so this check just confirms correlation doesn't care how long
# ago the underlying floods were captured, only that they're close to
# EACH OTHER.
result_backlog = collector3.ddos_correlation(DST)
assert result_backlog["distinct_flood_sources"] == 2, \
    f"FAIL: backlog must not break correlation -- both sources are only 0.5s apart at CAPTURE time: {result_backlog}"
assert result_backlog["is_ddos"], \
    f"FAIL: two genuinely-concurrent floods incorrectly NOT correlated under backlog: {result_backlog}"
print(f"PASS: correlation holds even when checked long after capture ({result_backlog})")

print()
print("--- Check 4: sentinel.py._run_dos() upgrades DoS to DDoS when correlated ---")
import pandas as pd
from sentinel import SentinelIPS

ips = SentinelIPS()

single_source_chunk = pd.DataFrame({
    "dos_flagged":  [True],
    "ddos_flagged": [False],
    "src_ip":       [SRC_C],
})
r1 = ips._run_dos(single_source_chunk)
assert r1.iloc[0]["sig_attack_type"] == "DoS", f"FAIL: single-source flood should stay DoS: {r1.iloc[0]}"

multi_source_chunk = pd.DataFrame({
    "dos_flagged":  [True],
    "ddos_flagged": [True],
    "src_ip":       [SRC_A],
})
r2 = ips._run_dos(multi_source_chunk)
assert r2.iloc[0]["sig_attack_type"] == "DDoS", f"FAIL: correlated multi-source flood should upgrade to DDoS: {r2.iloc[0]}"
print("PASS: _run_dos() correctly upgrades to DDoS only when ddos_flagged=True, stays DoS otherwise")

print()
print("All checks passed.")
