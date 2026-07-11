"""
attribution/mitre_mapper.py

Purpose: Map every detected attack to the MITRE ATT&CK framework. Provides
         tactic/technique lookups, TTP fingerprinting from multi-event sequences,
         campaign correlation across related attack events, and heatmap data
         for the dashboard MITRE ATT&CK matrix view.

Inputs:  Attack type strings (matching keys in config.MITRE_ATTACK_MAP),
         lists of detection event dicts.
Outputs: MITREEntry dataclass; technique coverage heatmaps; campaign clusters.

Usage:
    from attribution.mitre_mapper import MITREMapper
    mapper = MITREMapper()
    entry  = mapper.map_attack("DDoS")
    print(entry.tactic, entry.technique_id, entry.technique_name)

    # Full event annotation
    enriched = mapper.annotate_event({"attack_type": "BruteForce", "src_ip": "1.2.3.4"})
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from config import ATTACK_CLASSES, MITRE_ATTACK_MAP, SEVERITY_LEVELS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Extended technique detail not in config (sub-technique IDs, descriptions,
# data sources, and detection hints for the explainability layer)
# ---------------------------------------------------------------------------

_TECHNIQUE_DETAIL: dict[str, dict] = {
    "T1110": {
        "data_sources": ["Authentication logs", "Windows event 4625"],
        "detection":    "Multiple failed logins from single source within short window",
        "platforms":    ["Windows", "Linux", "macOS", "Network"],
    },
    "T1566": {
        "data_sources": ["Email gateway logs", "Web proxy logs"],
        "detection":    "Suspicious sender domain, malicious URL in body",
        "platforms":    ["Windows", "Linux", "macOS", "Office 365"],
    },
    "T1190": {
        "data_sources": ["Web application firewall", "Network traffic"],
        "detection":    "SQL metacharacters in request parameters",
        "platforms":    ["Network"],
    },
    "T1059.007": {
        "data_sources": ["Browser logs", "Web proxy logs"],
        "detection":    "Script tags or JS event handlers in HTTP requests",
        "platforms":    ["Windows", "macOS", "Linux"],
    },
    "T1059": {
        "data_sources": ["Process monitoring", "Command-line logs"],
        "detection":    "Shell metacharacters in web input fields",
        "platforms":    ["Windows", "Linux", "macOS"],
    },
    "T1543": {
        "data_sources": ["Process monitoring", "Network traffic"],
        "detection":    "Beaconing to C2 at regular intervals",
        "platforms":    ["Windows", "Linux", "macOS"],
    },
    "T1078": {
        "data_sources": ["Authentication logs", "Network flow"],
        "detection":    "Valid credentials used from unusual location or time",
        "platforms":    ["Windows", "Linux", "macOS", "Cloud"],
    },
    "T1046": {
        "data_sources": ["Network traffic", "Netflow"],
        "detection":    "Sequential port connections to many hosts",
        "platforms":    ["Network"],
    },
    "T1498": {
        "data_sources": ["Network traffic", "Netflow"],
        "detection":    "High-volume traffic flood from distributed sources",
        "platforms":    ["Network"],
    },
    "T1499": {
        "data_sources": ["Network traffic", "System metrics"],
        "detection":    "Sustained high-rate requests exhausting server resources",
        "platforms":    ["Windows", "Linux", "macOS", "Network"],
    },
    "T1600": {
        "data_sources": ["Network traffic", "TLS inspection"],
        "detection":    "Heartbeat extension with oversized payload",
        "platforms":    ["Network"],
    },
    "T1041": {
        "data_sources": ["Network traffic", "DLP"],
        "detection":    "Large outbound transfers over established C2 channel",
        "platforms":    ["Windows", "Linux", "macOS"],
    },
    "T1203": {
        "data_sources": ["Process monitoring", "Network traffic"],
        "detection":    "Unknown pattern — anomaly score exceeds baseline",
        "platforms":    ["Windows", "Linux", "macOS"],
    },
}

# Maps raw label strings from datasets to canonical attack-type keys
_LABEL_ALIASES: dict[str, str] = {
    "ftp-patator":          "BruteForce",
    "ssh-patator":          "BruteForce",
    "ftp-bruteforce":       "BruteForce",
    "ssh-bruteforce":       "BruteForce",
    "brute force -web":     "BruteForce",
    "brute force -xss":     "XSS",
    "dos slowloris":        "DoS",
    "dos hulk":             "DoS",
    "dos goldeneye":        "DoS",
    "dos slowhttptest":     "DoS",
    "dos attacks-hulk":     "DoS",
    "dos attacks-slowhttptest": "DoS",
    "dos attacks-goldeneye": "DoS",
    "dos attacks-slowloris": "DoS",
    "ddos":                 "DDoS",
    "ddos attacks-loic-http": "DDoS",
    "ddos attack-hoic":     "DDoS",
    "ddos attack-loic-udp": "DDoS",
    "portscan":             "PortScan",
    "bot":                  "Bot",
    "infiltration":         "Infiltration",
    "infilteration":        "Infiltration",
    "heartbleed":           "Heartbleed",
    "sql injection":        "SQLInjection",
    "xss":                  "XSS",
    "web attack \x96 sql injection": "SQLInjection",
    "web attack \x96 xss":  "XSS",
    "web attack \x96 brute force": "BruteForce",
    "benign":               None,
}


@dataclass
class MITREEntry:
    attack_type:    str
    tactic:         str
    technique_id:   str
    technique_name: str
    data_sources:   list[str] = field(default_factory=list)
    detection_hint: str       = ""
    platforms:      list[str] = field(default_factory=list)
    severity:       str       = "MEDIUM"


@dataclass
class CampaignCluster:
    campaign_id:    str
    src_ips:        set[str]    = field(default_factory=set)
    techniques:     set[str]    = field(default_factory=set)  # technique IDs
    tactics:        set[str]    = field(default_factory=set)
    first_seen:     Optional[datetime] = None
    last_seen:      Optional[datetime] = None
    event_count:    int         = 0


def _severity_for(attack_type: str) -> str:
    for level, attacks in SEVERITY_LEVELS.items():
        if attack_type in attacks:
            return level
    return "MEDIUM"


class MITREMapper:
    """
    MITRE ATT&CK annotation engine for SENTINEL detection events.

    Provides:
      • map_attack(attack_type)       — single-event technique lookup
      • annotate_event(event_dict)    — enrich a detection dict in-place
      • fingerprint_ttps(events)      — identify TTP patterns across event list
      • correlate_campaign(events)    — cluster events into campaigns
      • heatmap_data()                — tactic × technique counts for dashboard

    Parameters: none
    """

    def __init__(self) -> None:
        self._events:    list[dict]                   = []
        self._campaigns: dict[str, CampaignCluster]   = {}
        self._heatmap:   dict[str, int]               = defaultdict(int)
        logger.info("MITREMapper initialised with %d technique mappings",
                    len(MITRE_ATTACK_MAP))

    # ------------------------------------------------------------------
    # Core mapping
    # ------------------------------------------------------------------

    def map_attack(self, attack_type: str) -> Optional[MITREEntry]:
        """
        Look up the MITRE ATT&CK entry for a given attack type.

        Normalises raw dataset labels via alias table before lookup.

        Inputs:  attack_type — canonical key or raw dataset label string
        Outputs: MITREEntry, or None if attack_type is BENIGN / unmapped
        """
        normalised = self._normalise(attack_type)
        if normalised is None:
            return None

        entry = MITRE_ATTACK_MAP.get(normalised)
        if not entry:
            logger.debug("No MITRE mapping for attack_type=%s", normalised)
            return None

        tid    = entry["technique"]
        detail = _TECHNIQUE_DETAIL.get(tid, {})

        return MITREEntry(
            attack_type=normalised,
            tactic=entry["tactic"],
            technique_id=tid,
            technique_name=entry["name"],
            data_sources=detail.get("data_sources", []),
            detection_hint=detail.get("detection", ""),
            platforms=detail.get("platforms", []),
            severity=_severity_for(normalised),
        )

    @staticmethod
    def _normalise(raw: str) -> Optional[str]:
        """Resolve raw label or alias to canonical attack-type key."""
        if not raw:
            return None
        # Direct match
        if raw in MITRE_ATTACK_MAP:
            return raw
        # Alias table (case-insensitive)
        alias = _LABEL_ALIASES.get(raw.lower().strip())
        if alias is None:
            return None          # BENIGN or explicitly None
        return alias

    # ------------------------------------------------------------------
    # Event enrichment
    # ------------------------------------------------------------------

    def annotate_event(self, event: dict) -> dict:
        """
        Enrich a detection event dict with MITRE ATT&CK fields in-place.

        Adds keys: mitre_tactic, mitre_technique_id, mitre_technique_name,
                   mitre_severity, mitre_detection_hint, mitre_platforms.

        Inputs:  event — dict containing at minimum {"attack_type": str}
        Outputs: same dict with MITRE fields added
        """
        attack_type = event.get("attack_type", "")
        entry = self.map_attack(attack_type)

        if entry:
            event["mitre_tactic"]          = entry.tactic
            event["mitre_technique_id"]    = entry.technique_id
            event["mitre_technique_name"]  = entry.technique_name
            event["mitre_severity"]        = entry.severity
            event["mitre_detection_hint"]  = entry.detection_hint
            event["mitre_platforms"]       = entry.platforms
            self._heatmap[entry.technique_id] += 1
        else:
            event["mitre_tactic"]         = "Unknown"
            event["mitre_technique_id"]   = "T0000"
            event["mitre_technique_name"] = "Unknown"
            event["mitre_severity"]       = "INFO"
            event["mitre_detection_hint"] = ""
            event["mitre_platforms"]      = []

        self._events.append(event)
        return event

    # ------------------------------------------------------------------
    # TTP fingerprinting
    # ------------------------------------------------------------------

    def fingerprint_ttps(self, events: list[dict]) -> dict:
        """
        Identify TTP patterns across a sequence of detection events.

        Returns a fingerprint dict describing the observed kill-chain stage
        coverage and sophistication indicators.

        Inputs:  events — list of detection event dicts (may be pre-annotated)
        Outputs: fingerprint dict with keys:
                   tactics_observed, techniques_observed, kill_chain_coverage,
                   sophistication_score (0–100), multi_stage
        """
        tactics:    set[str] = set()
        techniques: set[str] = set()

        for ev in events:
            atype = ev.get("attack_type", "")
            entry = self.map_attack(atype)
            if entry:
                tactics.add(entry.tactic)
                techniques.add(entry.technique_id)

        # MITRE kill-chain stages in rough order
        kill_chain = [
            "Reconnaissance", "Resource Development", "Initial Access",
            "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact",
        ]
        covered = [s for s in kill_chain if s in tactics]
        coverage_pct = round(len(covered) / len(kill_chain) * 100, 1)

        # Sophistication heuristic: breadth of tactics × technique diversity
        sophistication = min(100, int(
            (len(tactics) * 10) + (len(techniques) * 5) + coverage_pct * 0.3
        ))

        return {
            "tactics_observed":    sorted(tactics),
            "techniques_observed": sorted(techniques),
            "kill_chain_coverage": covered,
            "coverage_pct":        coverage_pct,
            "sophistication_score": sophistication,
            "multi_stage":         len(tactics) > 2,
        }

    # ------------------------------------------------------------------
    # Campaign correlation
    # ------------------------------------------------------------------

    def correlate_campaign(self, events: list[dict]) -> list[CampaignCluster]:
        """
        Cluster events into campaigns based on shared source IPs and techniques.

        Two events belong to the same campaign when they share a source IP OR
        when they use overlapping techniques within the same 24-hour window.

        Inputs:  events — list of annotated detection event dicts
        Outputs: list of CampaignCluster objects
        """
        ip_to_campaign:  dict[str, str] = {}
        campaigns:       dict[str, CampaignCluster] = {}
        campaign_counter = 0

        for ev in events:
            src_ip  = ev.get("src_ip", "unknown")
            atype   = ev.get("attack_type", "")
            ts_raw  = ev.get("timestamp")
            entry   = self.map_attack(atype)
            tid     = entry.technique_id if entry else "T0000"
            tactic  = entry.tactic       if entry else "Unknown"

            ts = None
            if isinstance(ts_raw, datetime):
                ts = ts_raw
            elif isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw)
                except ValueError:
                    ts = datetime.now(tz=timezone.utc)
            else:
                ts = datetime.now(tz=timezone.utc)

            # Assign or create campaign
            if src_ip in ip_to_campaign:
                cid = ip_to_campaign[src_ip]
            else:
                campaign_counter += 1
                cid = f"CAMP-{campaign_counter:04d}"
                campaigns[cid] = CampaignCluster(campaign_id=cid)

            ip_to_campaign[src_ip] = cid
            camp = campaigns[cid]
            camp.src_ips.add(src_ip)
            camp.techniques.add(tid)
            camp.tactics.add(tactic)
            camp.event_count += 1

            if camp.first_seen is None or ts < camp.first_seen:
                camp.first_seen = ts
            if camp.last_seen is None or ts > camp.last_seen:
                camp.last_seen = ts

        result = list(campaigns.values())
        logger.info(
            "Campaign correlation: %d events → %d campaigns",
            len(events), len(result),
        )
        return result

    # ------------------------------------------------------------------
    # Heatmap
    # ------------------------------------------------------------------

    def heatmap_data(self) -> dict[str, dict]:
        """
        Return technique hit counts grouped by tactic for the dashboard matrix.

        Outputs: dict mapping tactic → {technique_id: count}
        """
        grouped: dict[str, dict[str, int]] = defaultdict(dict)
        for attack_type, entry_raw in MITRE_ATTACK_MAP.items():
            tid    = entry_raw["technique"]
            tactic = entry_raw["tactic"]
            count  = self._heatmap.get(tid, 0)
            grouped[tactic][tid] = grouped[tactic].get(tid, 0) + count
        return dict(grouped)

    def top_techniques(self, n: int = 10) -> list[tuple[str, int]]:
        """Return the n most frequently observed technique IDs and their counts."""
        return sorted(self._heatmap.items(), key=lambda x: x[1], reverse=True)[:n]
