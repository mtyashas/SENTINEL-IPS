"""
lab/m2_smoke_test.py

Purpose: M2 milestone smoke test (see lab/README.md) — confirm
         forensics.packet_logger.PacketLogger.start_live_capture() captures
         genuine packets off the lab's host-only network. Run from an
         elevated shell; Npcap capture on Windows requires Administrator.

Inputs:  --interface (Npcap device name), --bpf-filter, --duration (seconds
         to keep the capture open while traffic is generated from a VM).
Outputs: Prints logger_.summary() after the capture window closes.

Usage:
    venv\\Scripts\\python.exe lab\\m2_smoke_test.py --interface "Ethernet 2"
"""

import argparse
import logging
import sys
import time
from pathlib import Path

# Running this script directly (rather than via `python -m`) puts lab/ on
# sys.path instead of the project root, so the top-level `forensics` package
# isn't importable without this.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from forensics.packet_logger import PacketLogger

logging.basicConfig(level=logging.INFO)


def main() -> None:
    parser = argparse.ArgumentParser(description="M2 packet capture smoke test")
    parser.add_argument("--interface", default="Ethernet 2",
                         help="Npcap device name for the VirtualBox Host-Only adapter")
    parser.add_argument("--bpf-filter", default="net 192.168.56.0/24")
    parser.add_argument("--duration", type=int, default=20,
                         help="Seconds to capture before printing the summary")
    args = parser.parse_args()

    logger_ = PacketLogger()
    started = logger_.start_live_capture(interface=args.interface, bpf_filter=args.bpf_filter)
    if not started:
        print("Capture failed to start — check the interface name and Npcap install.")
        return

    print(f"Capturing for {args.duration}s on {args.interface!r} — "
          f"generate ping/curl traffic from a lab VM now.")
    time.sleep(args.duration)

    logger_.stop_live_capture()
    print(logger_.summary())


if __name__ == "__main__":
    main()
