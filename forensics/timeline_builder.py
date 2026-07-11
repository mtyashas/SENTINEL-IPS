"""
forensics/timeline_builder.py

Purpose: Reconstruct chronological attack timelines from collections of
         detection events. Groups events by source IP into campaigns,
         annotates each step with the MITRE ATT&CK kill-chain stage, and
         produces a human-readable attack narrative alongside structured
         timeline data for the dashboard and forensic reports.

Inputs:  list of detection event dicts (each must have at minimum
         src_ip, attack_type, timestamp).
Outputs: AttackTimeline dataclass with ordered TimelineEntry list;
         narrative string; kill-chain progression summary.

Usage:
    from forensics.timeline_builder import TimelineBuilder
    builder  = TimelineBuilder()
    timeline = builder.build(events)
    print(timeline.narrative)
    for entry in timeline.entries:
        print(entry.timestamp, entry.attack_type, entry.kill_chain_stage)
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

from config import MITRE_ATTACK_MAP, SEVERITY_LEVELS

logger = logging.getLogger(__name__)

# MITRE kill-chain stage ordering (Lockheed Martin / ATT&CK hybrid)
_KILL_CHAIN_ORDER: list[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Unknown",
]

# Tactic → stage index for sorting
_STAGE_IDX: dict[str, int] = {s: i for i, s in enumerate(_KILL_CHAIN_ORDER)}

# Gap between events before a new attack phase is declared (minutes)
_PHASE_GAP_MINUTES = 30


@dataclass
class TimelineEntry:
    sequence:        int
    timestamp:       datetime
    src_ip:          str
    attack_type:     str
    mitre_tactic:    str
    mitre_technique: str
    severity:        str
    kill_chain_stage: str
    kill_chain_idx:  int
    detail:          str
    is_phase_start:  bool = False   # True when gap since previous event > _PHASE_GAP_MINUTES


@dataclass
class AttackTimeline:
    campaign_id:      str
    src_ips:          list[str]
    start_time:       datetime
    end_time:         datetime
    duration_minutes: float
    entries:          list[TimelineEntry]
    kill_chain_stages_hit: list[str]
    sophistication:   str        # "Low" / "Medium" / "High" / "APT"
    narrative:        str
    event_count:      int
    attack_type_counts: dict[str, int] = field(default_factory=dict)


def _severity_for(attack_type: str) -> str:
    for level, attacks in SEVERITY_LEVELS.items():
        if attack_type in attacks:
            return level
    return "MEDIUM"


def _mitre_for(attack_type: str) -> tuple[str, str]:
    entry = MITRE_ATTACK_MAP.get(attack_type, {})
    return entry.get("tactic", "Unknown"), entry.get("technique", "T0000")


def _extract_ts(event: dict) -> datetime:
    raw = event.get("timestamp")
    if isinstance(raw, datetime):
        return raw.astimezone(timezone.utc) if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, str):
        try:
            dt = datetime.fromisoformat(raw)
            return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(tz=timezone.utc)


class TimelineBuilder:
    """
    Chronological attack-timeline reconstructor.

    Given an unordered list of detection events from one or more source IPs,
    produces:
      • Sorted TimelineEntry list annotated with MITRE ATT&CK stages
      • Kill-chain progression (which stages were observed)
      • Phase boundaries (pauses > 30 min between events)
      • Sophistication assessment based on stage breadth and tempo
      • Plain-English attack narrative for reporting

    Parameters: none
    """

    def __init__(self) -> None:
        logger.info("TimelineBuilder ready")

    # ------------------------------------------------------------------
    # Core build
    # ------------------------------------------------------------------

    def build(
        self,
        events:      list[dict],
        campaign_id: Optional[str] = None,
    ) -> AttackTimeline:
        """
        Build a complete attack timeline from a list of detection events.

        Events do not need to be pre-sorted — the builder sorts by timestamp.
        Events from multiple source IPs are merged into a single timeline
        (use build_per_ip() to get separate timelines per attacker).

        Inputs:
            events      — list of detection event dicts
            campaign_id — optional label; auto-generated if None
        Outputs: AttackTimeline dataclass
        """
        if not events:
            return self._empty_timeline(campaign_id or "CAMP-EMPTY")

        cid = campaign_id or f"CAMP-{datetime.now(tz=timezone.utc).strftime('%Y%m%d%H%M%S')}"

        # Sort by timestamp
        sorted_events = sorted(events, key=_extract_ts)

        entries:      list[TimelineEntry] = []
        prev_ts:      Optional[datetime]  = None
        type_counts:  dict[str, int]      = defaultdict(int)

        for seq, ev in enumerate(sorted_events, start=1):
            ts         = _extract_ts(ev)
            atype      = ev.get("attack_type", "Unknown")
            tactic     = ev.get("mitre_tactic")    or _mitre_for(atype)[0]
            technique  = ev.get("mitre_technique_id") or _mitre_for(atype)[1]
            severity   = ev.get("mitre_severity")  or _severity_for(atype)
            kc_stage   = tactic if tactic in _STAGE_IDX else "Unknown"
            kc_idx     = _STAGE_IDX.get(kc_stage, len(_KILL_CHAIN_ORDER) - 1)

            is_phase_start = False
            if prev_ts is not None:
                gap = (ts - prev_ts).total_seconds() / 60.0
                if gap >= _PHASE_GAP_MINUTES:
                    is_phase_start = True

            detail = ev.get("detail", "") or ev.get("mitre_detection_hint", "")

            entries.append(TimelineEntry(
                sequence=seq,
                timestamp=ts,
                src_ip=ev.get("src_ip", "Unknown"),
                attack_type=atype,
                mitre_tactic=tactic,
                mitre_technique=technique,
                severity=severity,
                kill_chain_stage=kc_stage,
                kill_chain_idx=kc_idx,
                detail=detail,
                is_phase_start=is_phase_start,
            ))

            type_counts[atype] += 1
            prev_ts = ts

        src_ips = sorted({e.src_ip for e in entries})
        start   = entries[0].timestamp
        end     = entries[-1].timestamp
        dur_min = round((end - start).total_seconds() / 60.0, 2)

        stages_hit = sorted(
            {e.kill_chain_stage for e in entries if e.kill_chain_stage != "Unknown"},
            key=lambda s: _STAGE_IDX.get(s, 99),
        )

        sophistication = self._assess_sophistication(entries, stages_hit, dur_min)
        narrative      = self._generate_narrative(cid, entries, stages_hit, sophistication, dur_min)

        logger.info(
            "Timeline built: campaign=%s, events=%d, stages=%d, sophistication=%s",
            cid, len(entries), len(stages_hit), sophistication,
        )

        return AttackTimeline(
            campaign_id=cid,
            src_ips=src_ips,
            start_time=start,
            end_time=end,
            duration_minutes=dur_min,
            entries=entries,
            kill_chain_stages_hit=stages_hit,
            sophistication=sophistication,
            narrative=narrative,
            event_count=len(entries),
            attack_type_counts=dict(type_counts),
        )

    def build_per_ip(self, events: list[dict]) -> dict[str, AttackTimeline]:
        """
        Build one timeline per unique source IP.

        Inputs:  events — list of detection event dicts (any source IPs mixed)
        Outputs: dict mapping src_ip → AttackTimeline
        """
        by_ip: dict[str, list[dict]] = defaultdict(list)
        for ev in events:
            by_ip[ev.get("src_ip", "Unknown")].append(ev)

        result: dict[str, AttackTimeline] = {}
        for ip, ip_events in by_ip.items():
            cid = f"IP-{ip.replace('.', '_')}"
            result[ip] = self.build(ip_events, campaign_id=cid)
        return result

    # ------------------------------------------------------------------
    # Sophistication assessment
    # ------------------------------------------------------------------

    @staticmethod
    def _assess_sophistication(
        entries:    list[TimelineEntry],
        stages_hit: list[str],
        dur_min:    float,
    ) -> str:
        stage_count = len(stages_hit)
        # Multi-stage with patience → APT
        lateral     = "Lateral Movement" in stages_hit
        persistence = "Persistence" in stages_hit
        evasion     = "Defense Evasion" in stages_hit
        patient     = dur_min > 60 and len(entries) < 50

        if stage_count >= 4 and (lateral or persistence) and evasion:
            return "APT"
        if stage_count >= 3 or (lateral and persistence):
            return "High"
        if stage_count >= 2 or patient:
            return "Medium"
        return "Low"

    # ------------------------------------------------------------------
    # Narrative generation
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_narrative(
        campaign_id:   str,
        entries:       list[TimelineEntry],
        stages_hit:    list[str],
        sophistication: str,
        dur_min:       float,
    ) -> str:
        if not entries:
            return "No events recorded."

        src_ips  = sorted({e.src_ip for e in entries})
        start    = entries[0].timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        end      = entries[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

        lines: list[str] = [
            f"ATTACK TIMELINE NARRATIVE — Campaign {campaign_id}",
            "=" * 60,
            f"Start      : {start}",
            f"End        : {end}",
            f"Duration   : {dur_min:.1f} minutes",
            f"Attackers  : {', '.join(src_ips)}",
            f"Events     : {len(entries)}",
            f"Kill-chain : {' -> '.join(stages_hit) if stages_hit else 'Single-stage'}",
            f"Assessed   : {sophistication} sophistication",
            "",
            "SEQUENCE OF EVENTS",
            "-" * 60,
        ]

        phase_num = 1
        for entry in entries:
            if entry.is_phase_start:
                phase_num += 1
                lines.append(f"\n[Phase {phase_num} — resumed after gap]")

            marker = ">>>" if entry.severity in ("CRITICAL", "HIGH") else "   "
            lines.append(
                f"{marker} [{entry.sequence:03d}] {entry.timestamp.strftime('%H:%M:%S')} "
                f"{entry.src_ip:<15} {entry.attack_type:<18} "
                f"{entry.mitre_technique} ({entry.mitre_tactic})"
            )
            if entry.detail:
                lines.append(f"           {entry.detail[:80]}")

        lines += [
            "",
            "KILL-CHAIN COVERAGE",
            "-" * 60,
        ]
        for stage in _KILL_CHAIN_ORDER:
            hit = stage in stages_hit
            lines.append(f"  {'[X]' if hit else '[ ]'} {stage}")

        lines += [
            "",
            f"CONCLUSION: This {'appears to be an Advanced Persistent Threat' if sophistication == 'APT' else 'is a ' + sophistication.lower() + '-sophistication attack'}.",
            "Recommend: Full forensic investigation, evidence preservation, and incident report.",
        ]

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_timeline(campaign_id: str) -> AttackTimeline:
        now = datetime.now(tz=timezone.utc)
        return AttackTimeline(
            campaign_id=campaign_id,
            src_ips=[],
            start_time=now,
            end_time=now,
            duration_minutes=0.0,
            entries=[],
            kill_chain_stages_hit=[],
            sophistication="Low",
            narrative="No events to reconstruct.",
            event_count=0,
        )
