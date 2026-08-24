"""
detection/layer2_signatures.py

Purpose: Signature-based detection for known attack payloads.
         Matches SQL injection, XSS, command injection, path traversal,
         phishing URLs, and brute-force indicators against compiled regex
         patterns sourced from config.py. Every detection is annotated with
         the corresponding MITRE ATT&CK tactic and technique.

Inputs:  Raw payload strings, URL strings, HTTP header dicts.
Outputs: Detection result dicts with keys:
           detected, attack_type, pattern_matched, severity,
           mitre_tactic, mitre_technique

Usage:
    from detection.layer2_signatures import SignatureDetector
    sig = SignatureDetector()
    result = sig.check_payload("SELECT * FROM users WHERE id=1 OR 1=1")
    if result["detected"]:
        print(result["attack_type"], result["mitre_technique"])
"""

import ipaddress
import logging
import re
from collections import OrderedDict
from typing import Dict, List, Optional
from urllib.parse import unquote, urlparse

from config import (
    COMMAND_INJECTION_PATTERNS,
    MITRE_ATTACK_MAP,
    SQL_INJECTION_PATTERNS,
    XSS_PATTERNS,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Additional patterns not in config.py
# ---------------------------------------------------------------------------

# Supplemental SQL injection patterns that cover SELECT/FROM statements,
# OR/AND tautologies (e.g. OR 1=1), and stacked-query markers not captured
# by the config.py set (which targets quote-based evasion variants).
_EXTRA_SQL_PATTERNS: List[str] = [
    r"\bSELECT\b.+\bFROM\b",          # bare SELECT ... FROM
    r"\bOR\s+[\w\d'\"]+\s*=\s*[\w\d'\"]+",  # OR 1=1 / OR 'a'='a'
    r"\bAND\s+[\w\d'\"]+\s*=\s*[\w\d'\"]+", # AND 1=1
    r"\bDELETE\s+FROM\b",
    r"\bUPDATE\b.+\bSET\b",
    r"\bWAITFOR\s+DELAY\b",            # time-based blind SQLi
    r"\bSLEEP\s*\(\s*\d+\s*\)",        # MySQL time-based blind
    r"\bBENCHMARK\s*\(",               # MySQL benchmark injection
    r";\s*(DROP|DELETE|UPDATE|INSERT)\b",  # stacked queries
]

_PATH_TRAVERSAL_PATTERNS: List[str] = [
    r"\.\./",
    r"\.\.[/\\]",
    r"%2e%2e[%2f%5c]",
    r"\.\.%2f",
    r"\.\.%5c",
    r"/etc/passwd",
    r"/etc/shadow",
    r"[Cc]:\\[Ww]indows",
]

_WEB_SHELL_PATTERNS: List[str] = [
    # Detection signatures only -- regex strings matched against captured
    # attacker payloads, never executed. PHP/ASP/JSP eval-style shells
    # wired to a superglobal/request param is the defining web-shell trait,
    # not just "eval(" alone (too broad, would match ordinary application
    # code that never touches request input).
    r"(eval|system|exec|passthru|shell_exec|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
    r"Runtime\.getRuntime\(\)\.exec",
    r"System\.Diagnostics\.Process",
    r"<%@\s*page.*Runtime",
    # Known public web-shell filenames commonly dropped/requested verbatim
    r"/(c99|r57|b374k|wso|webshell)\.(php|asp|aspx|jsp)",
]

_PHISHING_SUSPICIOUS_TLDS: List[str] = [
    ".tk", ".ml", ".ga", ".cf", ".xyz", ".gq", ".pw",
    ".top", ".work", ".click", ".download", ".loan",
]

_PHISHING_HOMOGRAPH_PATTERNS: List[str] = [
    r"paypa[l1][^a-z]",
    r"g[o0]{2}gle",
    r"micros[o0]ft",
    r"app[l1]e[^a-z]",
    r"arnazon",
    r"amazon[^.a-z]",
    r"faceb[o0]{2}k",
]

_PHISHING_SHORTENER_PATTERNS: List[str] = [
    r"bit\.ly/",
    r"tinyurl\.com/",
    r"t\.co/",
    r"goo\.gl/",
    r"is\.gd/",
]

# Raw-IP-as-host is a real phishing indicator for public IPs (masking the
# true destination), but a normal, benign pattern for internal tooling on
# a private network -- checked separately in check_url() so it can be
# skipped for private/loopback hosts instead of flagging every request in
# an internal deployment (or this project's own lab, which addresses every
# request by a 192.168.56.x host) as phishing.
_RAW_IP_URL_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/")

_BRUTE_FORCE_HEADER_PATTERNS: List[str] = [
    r"Basic\s+[A-Za-z0-9+/=]{4,}",   # many distinct Basic auth attempts
]

# CSRF only matters on endpoints that change state -- checking every GET
# would flag normal cross-site navigation constantly. Lab-fixture-specific
# (lab/target_service.py's /account/* routes); a real deployment would
# configure this per its own sensitive routes.
_CSRF_SENSITIVE_PATH_PREFIXES: List[str] = ["/account/"]
_CSRF_STATE_CHANGING_METHODS = ("POST", "PUT", "DELETE", "PATCH")

_CSRF_REQUEST_LINE_RE = re.compile(
    r"^(POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP/", re.MULTILINE
)
_CSRF_COOKIE_RE = re.compile(r"^Cookie:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_CSRF_SESSION_COOKIE_RE = re.compile(r"\bsession=([^;\s]+)", re.IGNORECASE)
_CSRF_HOST_RE   = re.compile(r"^Host:\s*([^\s:]+)", re.MULTILINE | re.IGNORECASE)
_CSRF_ORIGIN_RE = re.compile(r"^(?:Origin|Referer):\s*(\S+)", re.MULTILINE | re.IGNORECASE)

_SESSION_HISTORY_MAX_ENTRIES = 500   # bounds self._session_last_ip's growth
                                      # on a long-running server -- same class
                                      # of concern _conn_history's bounded
                                      # deques already address for beacon/DoS
                                      # in core/flow_collector.py.

# ---------------------------------------------------------------------------
# Severity lookup per attack type
# ---------------------------------------------------------------------------

_SEVERITY: Dict[str, str] = {
    "SQLInjection":   "MEDIUM",
    "XSS":            "MEDIUM",
    "CommandInject":  "HIGH",
    "PathTraversal":  "HIGH",
    "Phishing":       "LOW",
    "BruteForce":     "MEDIUM",
    "WebShell":       "CRITICAL",
    "CSRF":           "MEDIUM",
}


def _mitre(attack_type: str) -> Dict[str, str]:
    entry = MITRE_ATTACK_MAP.get(attack_type, {})
    return {
        "mitre_tactic":    entry.get("tactic",    "Unknown"),
        "mitre_technique": entry.get("technique", "Unknown"),
    }


def _no_detection() -> Dict:
    return {
        "detected":        False,
        "attack_type":     None,
        "pattern_matched": None,
        "severity":        None,
        "mitre_tactic":    None,
        "mitre_technique": None,
    }


def _detection(attack_type: str, pattern: str) -> Dict:
    return {
        "detected":        True,
        "attack_type":     attack_type,
        "pattern_matched": pattern,
        "severity":        _SEVERITY.get(attack_type, "MEDIUM"),
        **_mitre(attack_type),
    }


def _extract_session_cookie(raw_request: str) -> Optional[str]:
    """
    Pull the session-identifying cookie value out of a raw HTTP request,
    shared by check_csrf() and check_session_hijack() so the extraction
    logic exists in exactly one place.

    Falls back to the whole Cookie header when no cookie is specifically
    named "session" -- still a usable opaque identifier, just less precise
    than the named case.
    """
    cookie_match = _CSRF_COOKIE_RE.search(raw_request)
    if not cookie_match:
        return None
    cookie_header = cookie_match.group(1).strip()
    session_match = _CSRF_SESSION_COOKIE_RE.search(cookie_header)
    return session_match.group(1) if session_match else cookie_header


class SignatureDetector:
    """
    Layer 2 of the SENTINEL detection engine — signature matching.

    Compiles regex patterns at initialisation for O(1) per-pattern lookup.
    Each check_* method returns a single best-match detection dict.
    scan() aggregates all detections across all check methods.

    Parameters: none

    Usage:
        sig = SignatureDetector()
        result = sig.check_payload(payload_string)
        all_hits = sig.scan(raw_data)
    """

    def __init__(self) -> None:
        flags = re.IGNORECASE | re.DOTALL

        self._sql_re: List[re.Pattern] = [
            re.compile(p, flags) for p in SQL_INJECTION_PATTERNS + _EXTRA_SQL_PATTERNS
        ]
        self._xss_re: List[re.Pattern] = [
            re.compile(p, flags) for p in XSS_PATTERNS
        ]
        self._cmd_re: List[re.Pattern] = [
            re.compile(p, flags) for p in COMMAND_INJECTION_PATTERNS
        ]
        self._path_re: List[re.Pattern] = [
            re.compile(p, flags) for p in _PATH_TRAVERSAL_PATTERNS
        ]
        self._shell_re: List[re.Pattern] = [
            re.compile(p, flags) for p in _WEB_SHELL_PATTERNS
        ]
        self._phish_homo_re: List[re.Pattern] = [
            re.compile(p, flags) for p in _PHISHING_HOMOGRAPH_PATTERNS
        ]
        self._phish_url_re: List[re.Pattern] = [
            re.compile(p, flags) for p in _PHISHING_SHORTENER_PATTERNS
        ]
        self._brute_re: List[re.Pattern] = [
            re.compile(p, flags) for p in _BRUTE_FORCE_HEADER_PATTERNS
        ]

        # session token -> last source IP seen using it, for
        # check_session_hijack(). Bounded/LRU-evicted via OrderedDict, not a
        # plain dict, so a long-running server's session history doesn't
        # grow forever.
        self._session_last_ip: "OrderedDict[str, str]" = OrderedDict()

        logger.info(
            "SignatureDetector initialised — SQL:%d XSS:%d CMD:%d PATH:%d SHELL:%d",
            len(self._sql_re), len(self._xss_re),
            len(self._cmd_re), len(self._path_re), len(self._shell_re),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _first_match(
        self,
        text: str,
        patterns: List[re.Pattern],
        attack_type: str,
    ) -> Optional[Dict]:
        for rx in patterns:
            try:
                m = rx.search(text)
                if m:
                    return _detection(attack_type, rx.pattern)
            except Exception as exc:
                logger.debug("Pattern match error (%s): %s", attack_type, exc)
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_payload(self, payload: str) -> Dict:
        """
        Inspect an arbitrary payload string for injection or script attacks.

        Checks in priority order: SQL injection → XSS → command injection →
        path traversal. Returns the first match found.

        Inputs:  payload — raw request body, query string, or form value
        Outputs: detection dict (detected=False when clean)
        """
        if not payload:
            return _no_detection()

        try:
            decoded = unquote(payload)
        except Exception:
            decoded = payload

        for text in (payload, decoded):
            for patterns, atype in (
                (self._shell_re, "WebShell"),
                (self._sql_re,  "SQLInjection"),
                (self._xss_re,  "XSS"),
                (self._cmd_re,  "CommandInject"),
                (self._path_re, "PathTraversal"),
            ):
                hit = self._first_match(text, patterns, atype)
                if hit:
                    logger.debug("Payload hit: %s — %s", atype, hit["pattern_matched"][:60])
                    return hit

        return _no_detection()

    def check_url(self, url: str) -> Dict:
        """
        Inspect a URL for phishing or injection indicators.

        Checks: suspicious TLDs, homograph brand impersonation, URL shorteners,
        raw-IP hosts, and SQL/XSS payloads embedded in query strings.

        Inputs:  url — full URL string
        Outputs: detection dict
        """
        if not url:
            return _no_detection()

        try:
            decoded_url = unquote(url)
        except Exception:
            decoded_url = url

        url_lower = url.lower()

        # Suspicious TLD check
        for tld in _PHISHING_SUSPICIOUS_TLDS:
            # Match TLD at end of hostname segment (before path or query)
            if re.search(re.escape(tld) + r"[/?#\s]|" + re.escape(tld) + r"$", url_lower):
                return _detection("Phishing", f"suspicious_tld:{tld}")

        # Homograph / brand-impersonation check
        hit = self._first_match(url_lower, self._phish_homo_re, "Phishing")
        if hit:
            return hit

        # URL shortener check
        hit = self._first_match(decoded_url, self._phish_url_re, "Phishing")
        if hit:
            return hit

        # Raw-IP-as-host check, skipped for private/loopback IPs (see
        # _RAW_IP_URL_PATTERN comment)
        ip_match = _RAW_IP_URL_PATTERN.search(decoded_url)
        if ip_match:
            try:
                is_private = ipaddress.ip_address(ip_match.group(1)).is_private
            except ValueError:
                is_private = False
            if not is_private:
                return _detection("Phishing", "raw_ip_host")

        # Embedded injection in URL
        hit = self._first_match(decoded_url, self._sql_re, "SQLInjection")
        if hit:
            return hit

        hit = self._first_match(decoded_url, self._xss_re, "XSS")
        if hit:
            return hit

        return _no_detection()

    def check_headers(self, headers: Dict[str, str]) -> Dict:
        """
        Inspect HTTP headers for brute-force or injection indicators.

        Detects Basic-auth header volume, injected values in User-Agent /
        X-Forwarded-For / Referer, and unusual header combinations.

        Inputs:  headers — dict mapping header name to value
        Outputs: detection dict
        """
        if not headers:
            return _no_detection()

        for name, value in headers.items():
            if not isinstance(value, str):
                continue

            # Brute-force: Basic auth header present (caller tracks frequency)
            if name.lower() == "authorization":
                hit = self._first_match(value, self._brute_re, "BruteForce")
                if hit:
                    return hit

            # Injection in commonly-abused headers
            if name.lower() in ("user-agent", "referer", "x-forwarded-for", "cookie"):
                for patterns, atype in (
                    (self._sql_re,  "SQLInjection"),
                    (self._xss_re,  "XSS"),
                    (self._cmd_re,  "CommandInject"),
                ):
                    hit = self._first_match(value, patterns, atype)
                    if hit:
                        return hit

        return _no_detection()

    def check_csrf(self, raw_request: str) -> Dict:
        """
        Detect a forged cross-site request against a session-bearing,
        state-changing endpoint.

        Unlike every other check in this class, this isn't a payload
        signature -- a CSRF request's *body* is completely unremarkable
        (that's the point: it looks like an ordinary state-changing
        request). What's wrong is structural: it carries a session cookie
        (proving the victim's browser is authenticated) but has no
        Referer/Origin header naming this host, or names a different one
        entirely -- the tell that the request didn't originate from a page
        this site served.

        Only checked against _CSRF_SENSITIVE_PATH_PREFIXES (configured for
        this lab's /account/* routes) -- checking every state-changing
        request site-wide would need a real CSRF-token design decision
        this project hasn't made; this targets the specific gap being
        fixed.

        Note the response implication: the request that reaches the server
        in a CSRF attack comes from the *victim's own browser*, not the
        attacker's machine. Blocking src_ip (every other attack type's
        response) would block the victim, not the attacker -- callers
        should invalidate the returned session_token instead. See
        sentinel.py's _run_response() CSRF branch.

        Inputs:  raw_request — full raw HTTP request text (payload_sample)
        Outputs: detection dict, plus "session_token" (the "session"
                 cookie's value, or the whole Cookie header if no cookie
                 is specifically named "session") when detected
        """
        if not raw_request:
            return _no_detection()

        line_match = _CSRF_REQUEST_LINE_RE.match(raw_request)
        if not line_match:
            return _no_detection()
        method, path = line_match.group(1), line_match.group(2)
        if method not in _CSRF_STATE_CHANGING_METHODS:
            return _no_detection()
        if not any(path.startswith(p) for p in _CSRF_SENSITIVE_PATH_PREFIXES):
            return _no_detection()

        session_token = _extract_session_cookie(raw_request)
        if session_token is None:
            return _no_detection()   # no session to forge -- nothing at risk

        host_match   = _CSRF_HOST_RE.search(raw_request)
        host         = host_match.group(1) if host_match else ""
        origin_match = _CSRF_ORIGIN_RE.search(raw_request)
        if origin_match:
            origin_host = urlparse(origin_match.group(1)).hostname or origin_match.group(1)
            if host and origin_host == host:
                return _no_detection()   # same-origin Referer/Origin -- legitimate

        result = _detection("CSRF", f"{method} {path} (no matching Origin/Referer)")
        result["session_token"] = session_token
        return result

    def check_session_hijack(self, raw_request: str, src_ip: str) -> Dict:
        """
        Detect an existing session cookie suddenly being used from a
        different source IP -- the classic signature of a stolen or
        replayed session token. Unlike check_csrf() (a structural
        header-mismatch check, not tied to a specific cookie value), this
        tracks *continuity*: the same session token seen from a new src_ip
        it wasn't previously bound to.

        Checked against every request carrying a session cookie, not just
        state-changing requests to sensitive paths (check_csrf()'s scope)
        -- hijacking is meaningful on any authenticated request, not just
        ones that change state.

        Known limitation, same class as beacon_score()'s/connection_rate()'s
        own heuristics: a real client switching networks mid-session (WiFi
        to mobile) produces an identical signature to a stolen cookie -- no
        way to distinguish the two from network-layer data alone. Behind a
        NAT/proxy chain, the src_ip this sees may not be the true client IP
        either.

        Inputs:  raw_request -- full raw HTTP request text (payload_sample)
                 src_ip -- the flow's source IP
        Outputs: detection dict, plus "session_token" when detected (same
                 field CSRF uses -- the response is identical: invalidate
                 the session, never block src_ip, since src_ip here might
                 be the legitimate user who just changed networks, not the
                 thief)
        """
        session_token = _extract_session_cookie(raw_request)
        if session_token is None:
            return _no_detection()

        last_ip = self._session_last_ip.get(session_token)
        self._session_last_ip[session_token] = src_ip
        self._session_last_ip.move_to_end(session_token)
        if len(self._session_last_ip) > _SESSION_HISTORY_MAX_ENTRIES:
            self._session_last_ip.popitem(last=False)

        if last_ip is None or last_ip == src_ip:
            return _no_detection()   # first sighting, or same IP as before

        result = _detection("Session Hijacking",
                             f"session cookie switched from {last_ip} to {src_ip}")
        result["session_token"] = session_token
        return result

    def scan(self, data: str) -> List[Dict]:
        """
        Run all signature checks against a raw data string.

        Collects every distinct attack type found (not just the first). Useful
        for full forensic logging where multiple attack vectors may be present.

        Inputs:  data — raw string (payload, log line, reconstructed request)
        Outputs: list of detection dicts (empty list if clean)
        """
        if not data:
            return []

        detections: List[Dict] = []
        seen_types: set = set()

        checks = [
            (self._shell_re, "WebShell"),
            (self._sql_re,  "SQLInjection"),
            (self._xss_re,  "XSS"),
            (self._cmd_re,  "CommandInject"),
            (self._path_re, "PathTraversal"),
        ]

        try:
            decoded = unquote(data)
        except Exception:
            decoded = data

        for text in (data, decoded):
            for patterns, atype in checks:
                if atype in seen_types:
                    continue
                hit = self._first_match(text, patterns, atype)
                if hit:
                    detections.append(hit)
                    seen_types.add(atype)

        if detections:
            logger.info("scan() found %d attack type(s): %s", len(detections),
                        [d["attack_type"] for d in detections])

        return detections
