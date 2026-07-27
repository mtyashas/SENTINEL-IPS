"""
lab/replay_m5_verify_blacklist.py

Purpose: End-to-end confirmation that the two M5 fixes (2026-07-28: unreachable
         RESPONSE_MATRIX blocks, anomaly-baseline contamination) actually
         result in threat_intel/ip_blacklist.txt picking up the attacker IP.
         Replays the real, already-captured M5 pcap (real Kali attack traffic
         + real Ubuntu benign traffic, 205,111 packets) through the exact
         same SentinelIPS.process_chunk() pipeline sentinel.py live uses --
         the fixes were in detection/response logic, not packet capture, so
         this is a faithful end-to-end test without needing the VMs live.

Usage:
    python lab/replay_m5_verify_blacklist.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scapy.utils import rdpcap

from core.flow_collector import FlowCollector
from core.features import NetworkFeatureEngineer
from sentinel import SentinelIPS
from config import MODEL_DIR, REALTIME_CHUNK_SIZE

PCAP = str(MODEL_DIR.parent / "pcap" / "sentinel_20260727_130028_613ecac5.pcap")
ATTACKER_IP = "192.168.56.10"
BENIGN_IP   = "192.168.56.20"

print(f"Reprocessing real M5 capture: {PCAP}")
collector = FlowCollector()
for pkt in rdpcap(PCAP):
    collector.ingest_packet(pkt)
flows = collector.flush_all()
print(f"{len(flows)} flows assembled "
      f"({(flows['src_ip'] == ATTACKER_IP).sum()} from Kali, "
      f"{(flows['src_ip'] == BENIGN_IP).sum()} from Ubuntu benign)")

flows = NetworkFeatureEngineer(keep_raw=True).transform(flows)

ips = SentinelIPS(model_path=str(MODEL_DIR / "benchmarkids_binary.pkl"), enforce_blocks=False)

print("Feeding flows through the real detection+response pipeline...")
for start in range(0, len(flows), REALTIME_CHUNK_SIZE):
    chunk = flows.iloc[start:start + REALTIME_CHUNK_SIZE].copy()
    ips.process_chunk(chunk)

ips.summary()

print("\n" + "=" * 60)
print("BLACKLIST CHECK")
print("=" * 60)
kali_blocked   = ips._blacklist.is_blocked(ATTACKER_IP)
ubuntu_blocked = ips._blacklist.is_blocked(BENIGN_IP)
print(f"Kali (attacker, {ATTACKER_IP}) blocked:        {kali_blocked}")
print(f"Ubuntu (benign, {BENIGN_IP}) blocked:  {ubuntu_blocked}")

if kali_blocked and not ubuntu_blocked:
    print("\nPASS: attacker blacklisted, benign VM was not.")
elif kali_blocked and ubuntu_blocked:
    print("\nPARTIAL: attacker blacklisted, but so was the benign VM (false positive).")
else:
    print("\nFAIL: attacker was not blacklisted.")

ips.shutdown()
