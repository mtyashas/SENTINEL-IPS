# Security Findings — Deferred Fixes

Found during a full-codebase security audit on 2026-07-30. Not yet fixed —
tracked here so they don't get lost. Remove each entry once patched.

Both findings from the original audit were fixed 2026-08-01:
- Reflected XSS in `lab/target_service.py`'s `/search` — now escaped via
  `markupsafe.escape()`.
- PowerShell command-injection primitive in
  `response/connection_terminator.py`'s `terminate_ip()` — now validated
  with `ipaddress.ip_address()` before any PowerShell string is built,
  rejecting anything that doesn't parse as a real IP.

No open findings at present.
