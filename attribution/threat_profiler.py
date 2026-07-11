"""
attribution/threat_profiler.py

Purpose: Build and maintain persistent attacker profiles that classify threat
         actors as APT / Organised / Script-Kiddie / Insider based on observed
         TTP sophistication, attack tempo, target diversity, and evasion
         behaviour. Each profile accumulates evidence across multiple detection
         events from the same source IP so that classification improves over
         time.

Inputs:  Detection event dicts (must contain src_ip, attack_type, timestamp).
         GeoResult and MITREEntry objects from the other attribution modules.
Outputs: AttackerProfile dataclass; classification label; JSON-serialisable
         profile summary for the dashboard and forensics layer.

Usage:
    from attribution.threat_profiler import ThreatActorProfiler
    profiler = ThreatActorProfiler()
    profiler.ingest(event_dict)
    profile = profiler.get_profile("1.2.3.4")
    print(profile.actor_class, profile.sophistication_score)
"""

import json
import logging
import threading
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import MITRE_ATTACK_MAP, SEVERITY_LEVELS, THREAT_DIR

logger = logging.getLogger(__name__)

_PROFILE_PERSIST_PATH = THREAT_DIR / "attacker_profiles.jsonl"
_APT_SOPHISTICATION_THRESHOLD       = 60   # score ≥ this → APT
_ORGANISED_SOPHISTICATION_THRESHOLD = 35   # score ≥ this → Organised
_INSIDER_PORT_DIVERSITY_THRESHOLD   = 3    # few ports but high auth failures

# ---------------------------------------------------------------------------
# Classification scoring weights
# ---------------------------------------------------------------------------

# Each indicator contributes points toward the sophistication score (0–100)
_SCORE_WEIGHTS = {
    "multi_tactic":          15,   # observed > 2 distinct tactics
    "lateral_movement":      20,   # Lateral Movement tactic seen
    "persistence":           15,   # Persistence tactic seen
    "defence_evasion":       10,   # Defense Evasion tactic seen
    "slow_tempo":            10,   # < 10 events/hour (patient attacker)
    "high_target_diversity": 10,   # many distinct destination ports/hosts
    "repeated_attacker":     10,   # more than 5 prior events
    "vpn_or_proxy":          10,   # uses anonymisation infrastructure
}


@dataclass
class AttackerProfile:
    src_ip:              str
    actor_class:         str   = "Unknown"       # APT / Organised / ScriptKiddie / Insider
    sophistication_score: int  = 0               # 0–100
    first_seen:          Optional[datetime] = None
    last_seen:           Optional[datetime] = None
    event_count:         int   = 0
    attack_types:        dict  = field(default_factory=dict)    # type → count
    tactics_observed:    list  = field(default_factory=list)
    techniques_observed: list  = field(default_factory=list)
    dst_ports:           set   = field(default_factory=set)
    geo_country:         str   = "Unknown"
    geo_city:            str   = "Unknown"
    is_vpn_or_proxy:     bool  = False
    events_per_hour:     float = 0.0
    severity_counts:     dict  = field(default_factory=dict)    # CRITICAL/HIGH/etc → count
    notes:               list  = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["dst_ports"]           = list(self.dst_ports)
        d["tactics_observed"]    = list(self.tactics_observed)
        d["techniques_observed"] = list(self.techniques_observed)
        if self.first_seen:
            d["first_seen"] = self.first_seen.isoformat()
        if self.last_seen:
            d["last_seen"] = self.last_seen.isoformat()
        return d


def _severity_for(attack_type: str) -> str:
    for level, attacks in SEVERITY_LEVELS.items():
        if attack_type in attacks:
            return level
    return "MEDIUM"


def _extract_ts(event: dict) -> datetime:
    raw = event.get("timestamp")
    if isinstance(raw, datetime):
        return raw
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            pass
    return datetime.now(tz=timezone.utc)


class ThreatActorProfiler:
    """
    Incremental threat actor profiler that classifies attackers over time.

    Actor classification logic:
      APT          — sophistication ≥ 60; multi-tactic, patient, evasive
      Organised    — sophistication 35–59; consistent tooling, moderate tempo
      ScriptKiddie — sophistication < 35; noisy, single-vector, fast
      Insider      — legitimate source IP, low port diversity, auth failures

    Profiles are stored in memory and optionally persisted to
    threat_intel/attacker_profiles.jsonl for forensic continuity.

    Parameters:
        persist — if True, append each updated profile to disk (default True)
    """

    def __init__(self, persist: bool = True) -> None:
        self._profiles: dict[str, AttackerProfile] = {}
        self._lock      = threading.Lock()
        self._persist   = persist
        logger.info("ThreatActorProfiler ready (persist=%s)", persist)

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(
        self,
        event: dict,
        geo_country: str = "Unknown",
        geo_city:    str = "Unknown",
        is_vpn:      bool = False,
    ) -> AttackerProfile:
        """
        Update the attacker profile for the source IP in this event.

        Creates a new profile if the IP has not been seen before.
        Reclassifies the actor after every ingestion so the label stays
        current as evidence accumulates.

        Inputs:
            event       — detection dict with src_ip, attack_type, timestamp
            geo_country — country from Geolocator.locate()
            geo_city    — city from Geolocator.locate()
            is_vpn      — True if Geolocator flagged VPN/proxy
        Outputs: updated AttackerProfile
        """
        src_ip = event.get("src_ip", "unknown")
        ts     = _extract_ts(event)

        with self._lock:
            if src_ip not in self._profiles:
                self._profiles[src_ip] = AttackerProfile(src_ip=src_ip)

            profile = self._profiles[src_ip]
            self._update_fields(profile, event, ts, geo_country, geo_city, is_vpn)
            self._reclassify(profile)

            if self._persist:
                self._append_to_disk(profile)

        logger.debug(
            "Profile updated: %s → %s (score=%d)",
            src_ip, profile.actor_class, profile.sophistication_score,
        )
        return profile

    def _update_fields(
        self,
        profile:     AttackerProfile,
        event:       dict,
        ts:          datetime,
        geo_country: str,
        geo_city:    str,
        is_vpn:      bool,
    ) -> None:
        profile.event_count += 1
        profile.geo_country   = geo_country
        profile.geo_city      = geo_city
        profile.is_vpn_or_proxy = is_vpn or profile.is_vpn_or_proxy

        if profile.first_seen is None or ts < profile.first_seen:
            profile.first_seen = ts
        if profile.last_seen is None or ts > profile.last_seen:
            profile.last_seen = ts

        # Track time span and compute events-per-hour
        if profile.first_seen and profile.last_seen and profile.first_seen != profile.last_seen:
            span_h = (profile.last_seen - profile.first_seen).total_seconds() / 3600.0
            profile.events_per_hour = round(profile.event_count / max(span_h, 0.001), 2)

        # Attack type tallying
        atype = event.get("attack_type", "Unknown")
        profile.attack_types[atype] = profile.attack_types.get(atype, 0) + 1

        # Severity distribution
        sev = _severity_for(atype)
        profile.severity_counts[sev] = profile.severity_counts.get(sev, 0) + 1

        # MITRE tactic / technique from pre-annotated event fields
        tactic    = event.get("mitre_tactic", "")
        technique = event.get("mitre_technique_id", "")
        if tactic and tactic not in profile.tactics_observed:
            profile.tactics_observed.append(tactic)
        if technique and technique not in profile.techniques_observed:
            profile.techniques_observed.append(technique)

        # Destination port tracking (from flow features if present)
        dst_port = event.get("destination_port") or event.get("dst_port")
        if dst_port:
            try:
                profile.dst_ports.add(int(dst_port))
            except (ValueError, TypeError):
                pass

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _reclassify(self, profile: AttackerProfile) -> None:
        """Recompute sophistication score and actor class from current evidence."""
        score = 0
        notes: list[str] = []

        tactics = set(profile.tactics_observed)

        if len(tactics) > 2:
            score += _SCORE_WEIGHTS["multi_tactic"]
            notes.append("multi-tactic attacker")

        if "Lateral Movement" in tactics:
            score += _SCORE_WEIGHTS["lateral_movement"]
            notes.append("lateral movement observed")

        if "Persistence" in tactics:
            score += _SCORE_WEIGHTS["persistence"]
            notes.append("persistence mechanisms used")

        if "Defense Evasion" in tactics:
            score += _SCORE_WEIGHTS["defence_evasion"]
            notes.append("defence evasion observed")

        if 0 < profile.events_per_hour < 10:
            score += _SCORE_WEIGHTS["slow_tempo"]
            notes.append(f"slow tempo ({profile.events_per_hour:.1f} events/hr)")

        if len(profile.dst_ports) > 10:
            score += _SCORE_WEIGHTS["high_target_diversity"]
            notes.append(f"high port diversity ({len(profile.dst_ports)} ports)")

        if profile.event_count > 5:
            score += _SCORE_WEIGHTS["repeated_attacker"]
            notes.append(f"repeat attacker ({profile.event_count} events)")

        if profile.is_vpn_or_proxy:
            score += _SCORE_WEIGHTS["vpn_or_proxy"]
            notes.append("using VPN/proxy anonymisation")

        score = min(score, 100)
        profile.sophistication_score = score
        profile.notes = notes

        # Insider heuristic: private IP + auth failures + low port diversity
        is_private_ip = self._is_private(profile.src_ip)
        auth_failures  = (
            profile.attack_types.get("BruteForce", 0)
            + profile.attack_types.get("Infiltration", 0)
        )
        if is_private_ip and auth_failures > 0 and len(profile.dst_ports) <= _INSIDER_PORT_DIVERSITY_THRESHOLD:
            profile.actor_class = "Insider"
        elif score >= _APT_SOPHISTICATION_THRESHOLD:
            profile.actor_class = "APT"
        elif score >= _ORGANISED_SOPHISTICATION_THRESHOLD:
            profile.actor_class = "Organised"
        else:
            profile.actor_class = "ScriptKiddie"

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Check if IP falls in RFC 1918 / loopback ranges."""
        try:
            import ipaddress
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _append_to_disk(self, profile: AttackerProfile) -> None:
        try:
            with _PROFILE_PERSIST_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(profile.to_dict()) + "\n")
        except OSError as exc:
            logger.error("Profile persist failed for %s: %s", profile.src_ip, exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_profile(self, ip: str) -> Optional[AttackerProfile]:
        """
        Retrieve the current profile for a specific IP.

        Inputs:  ip — source IP string
        Outputs: AttackerProfile or None if never seen
        """
        with self._lock:
            return self._profiles.get(ip)

    def all_profiles(self) -> list[AttackerProfile]:
        """Return a snapshot of all current profiles, sorted by sophistication."""
        with self._lock:
            profiles = list(self._profiles.values())
        return sorted(profiles, key=lambda p: p.sophistication_score, reverse=True)

    def top_threats(self, n: int = 10) -> list[AttackerProfile]:
        """Return the n most sophisticated attacker profiles."""
        return self.all_profiles()[:n]

    def actor_class_distribution(self) -> dict[str, int]:
        """Count profiles per actor class for dashboard display."""
        counts: dict[str, int] = defaultdict(int)
        for p in self.all_profiles():
            counts[p.actor_class] += 1
        return dict(counts)

    def summary(self) -> dict:
        """Return aggregate profiler statistics."""
        profiles = self.all_profiles()
        if not profiles:
            return {"total_attackers": 0}
        apt_count = sum(1 for p in profiles if p.actor_class == "APT")
        return {
            "total_attackers":    len(profiles),
            "apt_count":          apt_count,
            "class_distribution": self.actor_class_distribution(),
            "top_attacker_ip":    profiles[0].src_ip if profiles else None,
            "max_sophistication": profiles[0].sophistication_score if profiles else 0,
        }
