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
         produce realistic multi-attempt traffic), echoes query
         parameters on /search (so SQLi/XSS-style payload strings show up
         as real HTTP traffic), accepts any file on /upload (so
         web-shell-shaped file content shows up as a real HTTP POST body),
         and issues a session cookie unconditionally on /account/login then
         accepts state-changing POSTs to /account/email with no CSRF-token
         check (so a forged cross-site request shows up as real traffic
         for detection/layer2_signatures.py's check_csrf() to catch) --
         none of it executed or stored anywhere.

Inputs:  None (HTTP requests from lab VMs).
Outputs: Plain-text HTTP responses; request details logged to stdout.

Usage:
    python lab/target_service.py --host 192.168.56.1 --port 80
"""

import argparse
import logging
import secrets
from typing import Tuple

from flask import Flask, request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("lab.target_service")

app = Flask(__name__)

# In-memory only, lab fixture -- not real session storage.
_ACTIVE_SESSIONS: set[str] = set()


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


@app.route("/upload", methods=["POST"])
def upload() -> Tuple[str, int]:
    f = request.files.get("file")
    if f is None:
        return "no file provided\n", 400
    content = f.read()
    logger.info("File upload: name=%r size=%d bytes", f.filename, len(content))
    return f"received {f.filename!r} ({len(content)} bytes) — not stored, lab fixture only\n", 200


@app.route("/account/login", methods=["POST"])
def account_login() -> Tuple[str, int]:
    """Issues a session cookie unconditionally -- no real auth, just
    something for /account/email's CSRF gap to be reachable through."""
    token = secrets.token_hex(16)
    _ACTIVE_SESSIONS.add(token)
    logger.info("Session issued: %s...", token[:8])
    resp = app.make_response("session established\n")
    resp.set_cookie("session", token)
    return resp


@app.route("/account/email", methods=["POST"])
def account_email() -> Tuple[str, int]:
    """State-changing action gated on the session cookie only -- no
    anti-CSRF token check, the exact gap detection/layer2_signatures.py's
    check_csrf() looks for (state-changing + session cookie present + no
    matching Origin/Referer)."""
    token = request.cookies.get("session", "")
    if token not in _ACTIVE_SESSIONS:
        return "not logged in\n", 401
    new_email = request.form.get("email", "")
    logger.info("Email change requested for session %s...: %r", token[:8], new_email)
    return f"email updated to {new_email!r} — not stored, lab fixture only\n", 200


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
