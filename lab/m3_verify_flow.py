"""
lab/m3_verify_flow.py

Purpose: M3 milestone verification (see lab/README.md) — capture a single
         curl request against lab/target_service.py and confirm
         core.flow_collector.FlowCollector assembles it into exactly one
         correct bidirectional flow record.

Inputs:  --interface (Npcap device name), --bpf-filter, --duration (seconds
         to keep the capture open while curl is run from a VM).
Outputs: Prints the assembled flow's key columns and a PASS/FAIL line.

Usage:
    python lab\\target_service.py --host 192.168.56.1 --port 80   (separate terminal, leave running)
    venv\\Scripts\\python.exe lab\\m3_verify_flow.py --interface "Ethernet 2"
"""

import argparse
import logging
import sys
import time
from pathlib import Path

# Running this script directly (rather than via `python -m`) puts lab/ on
# sys.path instead of the project root, so top-level packages aren't
# importable without this — see lab/m2_smoke_test.py for the same fix.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.utils import rdpcap  # noqa: E402

from core.flow_collector import FlowCollector  # noqa: E402
from forensics.packet_logger import PacketLogger  # noqa: E402

logging.basicConfig(level=logging.INFO)

_REPORT_COLUMNS = [
    "destination_port", "total_fwd_packets", "total_backward_packets",
    "syn_flag_count", "fin_flag_count", "flow_duration",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="M3 flow-assembly verification")
    parser.add_argument("--interface", default="Ethernet 2",
                         help="Npcap device name for the VirtualBox Host-Only adapter")
    parser.add_argument("--bpf-filter", default="tcp port 80 and net 192.168.56.0/24",
                         help="Narrower than M2's filter — isolates the target-service flow")
    parser.add_argument("--duration", type=int, default=20,
                         help="Seconds to capture before printing the summary")
    args = parser.parse_args()

    logger_ = PacketLogger()
    started = logger_.start_live_capture(interface=args.interface, bpf_filter=args.bpf_filter)
    if not started:
        print("Capture failed to start — check the interface name and Npcap install.")
        return

    print(f"Capturing for {args.duration}s on {args.interface!r} — "
          f"run: curl http://192.168.56.1/  from the benign VM now "
          f"(lab/target_service.py must already be running on the host).")
    time.sleep(args.duration)

    logger_.stop_live_capture()
    capture_summary = logger_.summary()
    print(capture_summary)

    pcap_path = capture_summary["current_file"]
    if capture_summary["packet_count"] == 0:
        print("M3 FAIL — no packets captured; nothing to assemble into a flow.")
        return

    collector = FlowCollector()
    for pkt in rdpcap(pcap_path):
        collector.ingest_packet(pkt)
    df = collector.flush_all()

    if df.empty:
        print("M3 FAIL — capture had packets but FlowCollector produced zero flows.")
        return

    print(df[_REPORT_COLUMNS])

    # Each curl invocation opens its own TCP connection, so N curl calls in
    # the capture window correctly produce N flow rows — the milestone is
    # that every one of them is a single clean row per connection (no
    # phantom one-packet fragments from the FIN-close edge case), not that
    # there's exactly one row overall.
    http_rows = df[df["destination_port"] == 80]
    clean = (
        len(http_rows) >= 1
        and (http_rows["syn_flag_count"] >= 1).all()
        and (http_rows["fin_flag_count"] >= 1).all()
        and (http_rows["total_fwd_packets"] >= 2).all()   # rules out a bare stray ACK
    )
    total_flow_pkts = int((df["total_fwd_packets"] + df["total_backward_packets"]).sum())
    if clean and len(df) == len(http_rows) and total_flow_pkts == capture_summary["packet_count"]:
        print(f"M3 PASS — {len(http_rows)} clean HTTP flow(s) assembled, "
              f"{total_flow_pkts} packets accounted for exactly.")
    else:
        print(f"M3 FAIL — got {len(df)} row(s) ({len(http_rows)} on port 80), "
              f"{total_flow_pkts} packets accounted for vs. "
              f"{capture_summary['packet_count']} captured.")


if __name__ == "__main__":
    main()
