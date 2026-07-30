# Security Findings — Deferred Fixes

Found during a full-codebase security audit on 2026-07-30. Not yet fixed —
tracked here so they don't get lost. Remove each entry once patched.

---

## 1. Reflected XSS — `lab/target_service.py:52`

**Status:** OPEN
**Severity:** Low (lab-only fixture, isolated VirtualBox host-only network — not internet-facing)

```python
@app.route("/search")
def search() -> str:
    query = request.args.get("q", "")
    logger.info("Search query received (%d chars)", len(query))
    return f"no results for: {query}\n"          # <-- unescaped reflection
```

`query` is echoed straight into the HTML response with no escaping, so any
HTML/JS in `?q=` executes in the browser of whoever views the response.

**Fix:**
```python
from markupsafe import escape
...
return f"no results for: {escape(query)}\n"
```
Doesn't affect the fixture's purpose — SENTINEL's detectors read payloads
off the packet capture, not the HTTP response body.

---

## 2. PowerShell command injection primitive — `response/connection_terminator.py:121-126`

**Status:** OPEN
**Severity:** Medium (latent — not reachable today, see note)

```python
ps_cmd = (
    f"Get-NetTCPConnection -State Established | "
    f"Where-Object {{$_.RemoteAddress -eq '{ip}'}} | "
    ...
)
result = subprocess.run(["powershell", "-NonInteractive", "-Command", ps_cmd], ...)
```

`ip` is interpolated unescaped inside a single-quoted PowerShell string
literal. A value containing `'` breaks out and runs arbitrary PowerShell
as a new pipeline stage.

**Why it's not urgent:** `ConnectionTerminator.terminate_ip()` is never
called anywhere in the live pipeline (`sentinel.py` only uses
`IPBlacklister.block()`), and every `ip` this project currently produces
comes from `str(ip.src)` in `core/flow_collector.py` — a Scapy-decoded IP
header field, which structurally cannot contain a quote. Becomes exploitable
the moment this class gets wired in with a less-constrained `ip` source
(e.g. a manual-block API, config value, or anything user-supplied).

**Fix:** don't interpolate into the script string — either validate first
(`ipaddress.ip_address(ip)`, reject on `ValueError`) or pass `ip` as a bound
PowerShell parameter instead of string-formatting it into the command.
