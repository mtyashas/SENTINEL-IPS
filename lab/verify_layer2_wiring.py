"""
lab/verify_layer2_wiring.py

Purpose: Self-check for wiring Layer 2 (signature detection) into the live
         pipeline (2026-07-28). Previously self._sig was instantiated in
         SentinelIPS.__init__ but never called anywhere -- this project's
         own SQLi test request (M5) went completely undetected because of
         it. Confirms, with real constructed packets (not mocked): a TCP
         payload carrying a SQLi pattern survives FlowCollector into
         payload_sample, gets matched by SentinelIPS._run_signatures(), and
         produces an event with attack_type=SQLInjection end to end.

Usage:
    python lab/verify_layer2_wiring.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from core.flow_collector import FlowCollector
from core.features import NetworkFeatureEngineer
from sentinel import SentinelIPS
from config import MODEL_DIR

CLIENT = ("10.0.0.5", 51000)
SERVER = ("10.0.0.1", 80)
SQLI_PAYLOAD = b"GET /search?q=' OR '1'='1 HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n"


def make_packet(src, dst, flags, payload=b"", seq=1000, ack=0):
    pkt = IP(src=src[0], dst=dst[0]) / TCP(sport=src[1], dport=dst[1], flags=flags, seq=seq, ack=ack)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


print("--- Building a synthetic flow with a SQLi-shaped GET request ---")
collector = FlowCollector()
pkts = [
    make_packet(CLIENT, SERVER, "S", seq=1000),
    make_packet(SERVER, CLIENT, "SA", seq=5000, ack=1001),
    make_packet(CLIENT, SERVER, "A", seq=1001, ack=5001),
    make_packet(CLIENT, SERVER, "PA", payload=SQLI_PAYLOAD, seq=1001, ack=5001),
    make_packet(SERVER, CLIENT, "A", seq=5001, ack=1001 + len(SQLI_PAYLOAD)),
    make_packet(SERVER, CLIENT, "FA", seq=5001, ack=1001 + len(SQLI_PAYLOAD)),
    make_packet(CLIENT, SERVER, "FA", seq=1001 + len(SQLI_PAYLOAD), ack=5002),
    make_packet(SERVER, CLIENT, "A", seq=5002, ack=1002 + len(SQLI_PAYLOAD)),
]
for pkt in pkts:
    collector.ingest_packet(pkt)
flows = collector.flush_all()
assert len(flows) == 1, f"expected exactly 1 flow, got {len(flows)}"

row = flows.iloc[0]
assert "OR '1'='1" in row["payload_sample"], (
    f"payload_sample did not survive FlowCollector: {row['payload_sample']!r}"
)
print(f"OK: payload_sample captured ({len(row['payload_sample'])} chars): "
      f"{row['payload_sample'][:50]!r}...")

print("\n--- Feeding through the real SentinelIPS pipeline ---")
flows = NetworkFeatureEngineer(keep_raw=True).transform(flows)
ips = SentinelIPS(model_path=str(MODEL_DIR / "benchmarkids_binary.pkl"))
result = ips.process_chunk(flows)

assert result.iloc[0]["pred_binary"] == 1, "signature hit must promote pred_binary to 1"
assert result.iloc[0]["confidence"] >= 0.90, "signature hit must floor confidence at 0.90"
assert result.iloc[0]["sig_attack_type"] == "SQLInjection", (
    f"expected sig_attack_type=SQLInjection, got {result.iloc[0]['sig_attack_type']!r}"
)
print(f"OK: pred_binary={result.iloc[0]['pred_binary']}, "
      f"confidence={result.iloc[0]['confidence']:.2f}, "
      f"sig_attack_type={result.iloc[0]['sig_attack_type']!r}")

event = ips._build_event(result.iloc[0])
assert event["attack_type"] == "SQLInjection", (
    f"_build_event must prefer sig_attack_type; got {event['attack_type']!r}"
)
assert event["severity"] == "MEDIUM"
print(f"OK: _build_event() -> attack_type={event['attack_type']!r}, "
      f"severity={event['severity']!r}")

print("\nAll Layer 2 wiring checks passed.")
