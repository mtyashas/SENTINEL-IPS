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

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import unquote

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

_PHISHING_URL_PATTERNS: List[str] = [
    r"bit\.ly/",
    r"tinyurl\.com/",
    r"t\.co/",
    r"goo\.gl/",
    r"is\.gd/",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/",   # raw-IP URLs
]

_BRUTE_FORCE_HEADER_PATTERNS: List[str] = [
    r"Basic\s+[A-Za-z0-9+/=]{4,}",   # many distinct Basic auth attempts
]

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
        self._phish_homo_re: List[re.Pattern] = [
            re.compile(p, flags) for p in _PHISHING_HOMOGRAPH_PATTERNS
        ]
        self._phish_url_re: List[re.Pattern] = [
            re.compile(p, flags) for p in _PHISHING_URL_PATTERNS
        ]
        self._brute_re: List[re.Pattern] = [
            re.compile(p, flags) for p in _BRUTE_FORCE_HEADER_PATTERNS
        ]

        logger.info(
            "SignatureDetector initialised — SQL:%d XSS:%d CMD:%d PATH:%d",
            len(self._sql_re), len(self._xss_re),
            len(self._cmd_re), len(self._path_re),
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

        # URL shortener / raw-IP check
        hit = self._first_match(decoded_url, self._phish_url_re, "Phishing")
        if hit:
            return hit

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
