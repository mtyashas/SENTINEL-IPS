"""
lab/verify_syn_port_reuse.py

Purpose: Self-check for the SYN-port-reuse flow-merging bug found while
         investigating why a real SQLi request went undetected in the M5
         replay (2026-07-28). An hping3 flood packet left a flow open
         (never closed by RST/FIN); 215 seconds later curl's SQLi request
         reused the same ephemeral source port, and FlowCollector merged
         it into the stale flow -- losing the real request's payload to
         payload_sample's first-write-wins rule. Confirms: (1) a fresh SYN
         on an idle open flow force-closes the old one and starts fresh,
         (2) a rapid SYN retransmission during an in-progress handshake is
         NOT mistaken for a new connection.

Usage:
    python lab/verify_syn_port_reuse.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from core.flow_collector import FlowCollector

ATTACKER = ("192.168.56.10", 53112)   # port deliberately reused
SERVER   = ("192.168.56.1", 80)


def pkt(src, dst, flags, t, payload=b"", seq=1000, ack=0):
    p = IP(src=src[0], dst=dst[0]) / TCP(sport=src[1], dport=dst[1], flags=flags, seq=seq, ack=ack)
    if payload:
        p = p / Raw(load=payload)
    p.time = t
    return p


def check_stale_flow_reuse_after_long_gap():
    print("--- Check 1: SYN reusing a port idle 215s force-closes the stale flow ---")
    collector = FlowCollector()

    # Old flow: a bare SYN that never gets a real close (flood-shaped).
    collector.ingest_packet(pkt(ATTACKER, SERVER, "S", t=1000.0))

    # 215s later: a genuinely new connection reuses the exact same port,
    # with a real HTTP request as its payload.
    real_request = b"GET /search?q=' OR '1'='1 HTTP/1.1\r\nHost: 192.168.56.1\r\n\r\n"
    collector.ingest_packet(pkt(ATTACKER, SERVER, "S",  t=1215.0, seq=5000))
    collector.ingest_packet(pkt(SERVER, ATTACKER, "SA", t=1215.001, seq=9000, ack=5001))
    collector.ingest_packet(pkt(ATTACKER, SERVER, "A",  t=1215.002, seq=5001, ack=9001))
    collector.ingest_packet(pkt(ATTACKER, SERVER, "PA", t=1215.003, seq=5001, ack=9001, payload=real_request))

    flows = collector.flush_all()
    assert len(flows) == 2, f"expected the stale flow + the new one as 2 separate rows, got {len(flows)}"

    new_flow = flows[flows["payload_sample"].str.contains("search", na=False)]
    assert len(new_flow) == 1, "the real request's payload must survive into its own flow row"
    assert "OR '1'='1" in new_flow.iloc[0]["payload_sample"]
    print(f"OK: 2 flow rows produced; new connection's real payload intact: "
          f"{new_flow.iloc[0]['payload_sample'][:50]!r}...")


def check_rapid_syn_retransmit_not_split():
    print("\n--- Check 2: a rapid SYN retransmission (<3s) is NOT treated as a new flow ---")
    collector = FlowCollector()
    collector.ingest_packet(pkt(ATTACKER, SERVER, "S", t=2000.0, seq=7000))
    # Retransmitted SYN 1.2s later (typical RTO) -- same in-progress handshake.
    collector.ingest_packet(pkt(ATTACKER, SERVER, "S", t=2001.2, seq=7000))
    collector.ingest_packet(pkt(SERVER, ATTACKER, "SA", t=2001.3, seq=8000, ack=7001))
    collector.ingest_packet(pkt(ATTACKER, SERVER, "A", t=2001.4, seq=7001, ack=8001))

    flows = collector.flush_all()
    assert len(flows) == 1, (
        f"a rapid SYN retransmission must not split one handshake into two flows, got {len(flows)}"
    )
    print("OK: rapid SYN retransmit correctly stayed part of the same flow")


if __name__ == "__main__":
    check_stale_flow_reuse_after_long_gap()
    check_rapid_syn_retransmit_not_split()
    print("\nAll SYN-port-reuse checks passed.")
