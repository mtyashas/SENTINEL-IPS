"""
lab/target_service.py

Purpose: Minimal HTTP fixture for the live-traffic validation lab (see
         lab/README.md). Gives the benign VM (curl/browsing) and the
         attacker VM (nmap/hydra/curl-with-payloads) something real to
         connect to on the host, so core.flow_collector.FlowCollector has
         genuine TCP flows to assemble instead of degenerate ICMP pings.

         This is a lab fixture only — not one of SENTINEL's 32 production
         modules, and not a hardened application. It intentionally accepts
         any username/password on /login (so hydra brute-force runs
         produce realistic multi-attempt traffic) and echoes query
         parameters on /search (so SQLi/XSS-style payload strings show up
         as real HTTP traffic) without executing or storing them anywhere.

Inputs:  None (HTTP requests from lab VMs).
Outputs: Plain-text HTTP responses; request details logged to stdout.

Usage:
    python lab/target_service.py --host 192.168.56.1 --port 80
"""

import argparse
import logging
from typing import Tuple

from flask import Flask, request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("lab.target_service")

app = Flask(__name__)


@app.route("/")
def index() -> str:
    return "SENTINEL lab target service — OK\n"


@app.route("/login", methods=["POST"])
def login() -> Tuple[str, int]:
    username = request.form.get("username", "")
    logger.info("Login attempt: username=%r", username)
    return "invalid credentials\n", 401


@app.route("/search")
def search() -> str:
    query = request.args.get("q", "")
    logger.info("Search query received (%d chars)", len(query))
    return f"no results for: {query}\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="SENTINEL lab target service")
    parser.add_argument("--host", default="192.168.56.1",
                         help="Bind address (default: lab host-only adapter IP)")
    parser.add_argument("--port", type=int, default=80,
                         help="Bind port (default: 80 — binding to it may "
                              "require an elevated/Administrator shell)")
    args = parser.parse_args()

    logger.info("Starting lab target service on %s:%d", args.host, args.port)
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
