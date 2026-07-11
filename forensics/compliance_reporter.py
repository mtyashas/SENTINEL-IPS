"""
forensics/compliance_reporter.py

Purpose: Generate audit-ready compliance reports from SENTINEL detection data.
         Supports two regulatory frameworks:
           GDPR Article 33  — 72-hour data breach notification to supervisory authority
           ISO/IEC 27001 A.16 — Information security incident management report

         Both report types are written as JSON (machine-readable) and plain-text
         (human-readable) to reports/. IP addresses in GDPR reports are
         pseudonymised by default to satisfy data-minimisation requirements.

Inputs:  AttackTimeline (from timeline_builder) or list of detection events;
         optional organisation metadata dict.
Outputs: ComplianceReport dataclass; files written to reports/.

Usage:
    from forensics.compliance_reporter import ComplianceReporter
    reporter = ComplianceReporter(org_name="Acme Corp", dpo_email="dpo@acme.com")
    report   = reporter.gdpr_breach_report(timeline)
    iso_rpt  = reporter.iso27001_incident_report(timeline)
    print(report.report_id, report.output_path)
"""

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import REPORT_DIR

logger = logging.getLogger(__name__)

_GDPR_SCHEMA_VERSION   = "GDPR-Art33-v1.0"
_ISO_SCHEMA_VERSION    = "ISO27001-A16-v1.0"
_PSEUDONYM_SALT        = "SENTINEL_IPS_SALT_2024"


def _pseudonymise(ip: str) -> str:
    """One-way hash of an IP for GDPR data-minimisation (SHA-256, first 12 hex chars)."""
    raw = (ip + _PSEUDONYM_SALT).encode()
    return "ANON-" + hashlib.sha256(raw).hexdigest()[:12].upper()


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _report_id(prefix: str) -> str:
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{prefix}-{ts}"


@dataclass
class ComplianceReport:
    report_id:    str
    framework:    str           # "GDPR-Art33" or "ISO27001-A16"
    generated_at: str
    output_path:  Path
    summary:      str


class ComplianceReporter:
    """
    Dual-framework compliance report generator.

    Generates:
      GDPR Article 33 — mandatory 72-hour breach notification including:
        • Nature of the breach, categories and approximate count of data subjects
        • Likely consequences and measures taken / proposed
        • DPO contact details

      ISO 27001 A.16 — incident management record including:
        • Incident classification and severity
        • Timeline of detection, containment, eradication, recovery
        • Root cause analysis (derived from kill-chain)
        • Lessons learned and corrective actions

    Parameters:
        org_name    — organisation name for report headers
        dpo_email   — Data Protection Officer email (GDPR reports)
        report_dir  — output directory (default config.REPORT_DIR)
        pseudonymise — anonymise IP addresses in GDPR reports (default True)
    """

    def __init__(
        self,
        org_name:     str           = "Unknown Organisation",
        dpo_email:    str           = "dpo@example.com",
        report_dir:   Optional[Path] = None,
        pseudonymise: bool           = True,
    ) -> None:
        self._org          = org_name
        self._dpo_email    = dpo_email
        self._report_dir   = report_dir or REPORT_DIR
        self._pseudonymise = pseudonymise
        logger.info(
            "ComplianceReporter ready — org=%s, pseudonymise=%s",
            org_name, pseudonymise,
        )

    # ------------------------------------------------------------------
    # GDPR Article 33
    # ------------------------------------------------------------------

    def gdpr_breach_report(
        self,
        timeline_or_events,
        incident_description: str = "",
        affected_subjects:    int = 0,
        data_categories:      Optional[list[str]] = None,
    ) -> ComplianceReport:
        """
        Generate a GDPR Article 33 data-breach notification report.

        Inputs:
            timeline_or_events   — AttackTimeline or list of detection event dicts
            incident_description — free-text description of the incident
            affected_subjects    — estimated number of affected data subjects
            data_categories      — types of personal data involved (e.g. ["IP", "email"])
        Outputs: ComplianceReport with path to JSON + text files
        """
        from forensics.timeline_builder import AttackTimeline

        if isinstance(timeline_or_events, AttackTimeline):
            tl = timeline_or_events
            events = tl.entries
            src_ips   = tl.src_ips
            start_iso = tl.start_time.isoformat()
            end_iso   = tl.end_time.isoformat()
            attack_types = list(tl.attack_type_counts.keys())
        else:
            events    = timeline_or_events or []
            src_ips   = list({e.get("src_ip", "") for e in events if e.get("src_ip")})
            start_iso = _now_iso()
            end_iso   = _now_iso()
            attack_types = list({e.get("attack_type", "") for e in events})

        rid = _report_id("GDPR")

        # Pseudonymise IPs if required
        if self._pseudonymise:
            reported_ips = [_pseudonymise(ip) for ip in src_ips]
        else:
            reported_ips = src_ips

        doc = {
            "schema":           _GDPR_SCHEMA_VERSION,
            "report_id":        rid,
            "generated_at":     _now_iso(),
            "organisation":     self._org,
            "dpo_contact":      self._dpo_email,
            "notification_deadline": "Within 72 hours of becoming aware of the breach",
            "section_1_nature_of_breach": {
                "description":       incident_description or self._auto_description(attack_types),
                "attack_types":      attack_types,
                "breach_start":      start_iso,
                "breach_end":        end_iso,
                "source_identifiers": reported_ips,
                "ip_pseudonymised":  self._pseudonymise,
            },
            "section_2_data_subjects": {
                "approximate_count":    affected_subjects,
                "categories_of_data":   data_categories or ["Network traffic metadata", "IP addresses"],
                "categories_of_people": ["Users of protected systems"],
            },
            "section_3_consequences": {
                "likely_consequences": self._assess_consequences(attack_types),
                "severity":            self._breach_severity(attack_types),
            },
            "section_4_measures": {
                "measures_taken": [
                    "Malicious IP addresses automatically blocked by SENTINEL IPS",
                    "Affected connections terminated",
                    "Full packet capture preserved as forensic evidence",
                    "Incident timeline reconstructed",
                    "Adaptive model retrain scheduled to prevent recurrence",
                ],
                "measures_proposed": [
                    "Review and harden firewall rules",
                    "Notify affected data subjects if high-risk breach confirmed",
                    "Conduct penetration test to identify remaining vulnerabilities",
                ],
            },
        }

        return self._write_report(doc, rid, "GDPR-Art33", self._gdpr_text(doc))

    def _auto_description(self, attack_types: list[str]) -> str:
        if not attack_types:
            return "Unclassified security incident detected by SENTINEL IPS."
        types_str = ", ".join(attack_types)
        return (
            f"SENTINEL IPS detected and blocked a security incident involving "
            f"the following attack types: {types_str}. "
            f"Network traffic was captured and analysed."
        )

    @staticmethod
    def _assess_consequences(attack_types: list[str]) -> list[str]:
        consequences: list[str] = []
        if any(t in attack_types for t in ("SQLInjection", "Infiltration")):
            consequences.append("Potential unauthorised access to personal data")
        if any(t in attack_types for t in ("DDoS", "DoS")):
            consequences.append("Temporary loss of availability of services")
        if any(t in attack_types for t in ("BruteForce", "XSS")):
            consequences.append("Potential credential compromise or session hijacking")
        if "Bot" in attack_types or "APT" in attack_types:
            consequences.append("Potential persistent access by threat actor")
        if not consequences:
            consequences.append("Potential disruption to network services")
        return consequences

    @staticmethod
    def _breach_severity(attack_types: list[str]) -> str:
        critical = {"Infiltration", "ZeroDay", "APT", "Heartbleed"}
        high     = {"DDoS", "DoS", "Bot", "Ransomware"}
        if any(t in critical for t in attack_types):
            return "HIGH — Likely requires notification to supervisory authority AND data subjects"
        if any(t in high for t in attack_types):
            return "MEDIUM — Requires notification to supervisory authority"
        return "LOW — Document internally; notify authority if doubt"

    @staticmethod
    def _gdpr_text(doc: dict) -> str:
        d = doc
        s1 = d["section_1_nature_of_breach"]
        s2 = d["section_2_data_subjects"]
        s3 = d["section_3_consequences"]
        s4 = d["section_4_measures"]

        lines = [
            f"GDPR ARTICLE 33 — DATA BREACH NOTIFICATION",
            "=" * 60,
            f"Report ID    : {d['report_id']}",
            f"Generated    : {d['generated_at']}",
            f"Organisation : {d['organisation']}",
            f"DPO Contact  : {d['dpo_contact']}",
            f"Deadline     : {d['notification_deadline']}",
            "",
            "SECTION 1 — NATURE OF THE PERSONAL DATA BREACH",
            "-" * 60,
            f"Description  : {s1['description']}",
            f"Attack Types : {', '.join(s1['attack_types']) or 'Unknown'}",
            f"Period       : {s1['breach_start']} to {s1['breach_end']}",
            f"Sources      : {', '.join(s1['source_identifiers'][:10])} "
            f"{'(IPs pseudonymised)' if s1['ip_pseudonymised'] else ''}",
            "",
            "SECTION 2 — CATEGORIES AND NUMBER OF DATA SUBJECTS",
            "-" * 60,
            f"Approximate subjects : {s2['approximate_count']}",
            f"Data categories      : {', '.join(s2['categories_of_data'])}",
            f"Affected persons     : {', '.join(s2['categories_of_people'])}",
            "",
            "SECTION 3 — LIKELY CONSEQUENCES",
            "-" * 60,
            f"Severity     : {s3['severity']}",
        ]
        for c in s3["likely_consequences"]:
            lines.append(f"  - {c}")
        lines += [
            "",
            "SECTION 4 — MEASURES TAKEN AND PROPOSED",
            "-" * 60,
            "Measures taken:",
        ]
        for m in s4["measures_taken"]:
            lines.append(f"  [X] {m}")
        lines.append("Measures proposed:")
        for m in s4["measures_proposed"]:
            lines.append(f"  [ ] {m}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # ISO 27001 A.16
    # ------------------------------------------------------------------

    def iso27001_incident_report(
        self,
        timeline_or_events,
        root_cause:     str = "",
        responder_name: str = "SENTINEL IPS (automated)",
    ) -> ComplianceReport:
        """
        Generate an ISO/IEC 27001 Annex A.16 incident management report.

        Inputs:
            timeline_or_events — AttackTimeline or list of detection event dicts
            root_cause         — free-text root cause analysis (optional)
            responder_name     — name of incident responder / team
        Outputs: ComplianceReport
        """
        from forensics.timeline_builder import AttackTimeline

        if isinstance(timeline_or_events, AttackTimeline):
            tl = timeline_or_events
            stages    = tl.kill_chain_stages_hit
            soph      = tl.sophistication
            dur_min   = tl.duration_minutes
            start_iso = tl.start_time.isoformat()
            end_iso   = tl.end_time.isoformat()
            attack_types = list(tl.attack_type_counts.keys())
            event_count  = tl.event_count
            campaign_id  = tl.campaign_id
        else:
            events     = timeline_or_events or []
            stages     = []
            soph       = "Unknown"
            dur_min    = 0.0
            start_iso  = _now_iso()
            end_iso    = _now_iso()
            attack_types = list({e.get("attack_type", "") for e in events})
            event_count  = len(events)
            campaign_id  = "UNKNOWN"

        rid = _report_id("ISO")
        severity = self._breach_severity(attack_types)

        doc = {
            "schema":          _ISO_SCHEMA_VERSION,
            "report_id":       rid,
            "generated_at":    _now_iso(),
            "organisation":    self._org,
            "responder":       responder_name,
            "incident": {
                "campaign_id":   campaign_id,
                "classification": self._classify_incident(attack_types),
                "severity":       severity.split(" — ")[0],
                "start_time":     start_iso,
                "end_time":       end_iso,
                "duration_min":   dur_min,
                "event_count":    event_count,
                "attack_types":   attack_types,
                "kill_chain_stages": stages,
                "sophistication":    soph,
            },
            "detection_and_containment": {
                "detected_by":      "SENTINEL IPS v2.0 — automated ML + signature detection",
                "containment_actions": [
                    "Malicious source IPs automatically blocked via OS firewall",
                    "Active TCP connections terminated",
                    "Rate limiting applied to suspicious traffic flows",
                    "Session tokens for potentially compromised accounts revoked",
                ],
            },
            "eradication_and_recovery": {
                "root_cause":       root_cause or self._auto_root_cause(attack_types, stages),
                "eradication":      self._eradication_steps(attack_types),
                "recovery_status":  "Automated response completed; manual review recommended",
            },
            "lessons_learned": {
                "corrective_actions": self._corrective_actions(attack_types, soph),
                "preventive_measures": [
                    "Adaptive model retrain scheduled to improve future detection",
                    "Zero-day patterns added to threat intelligence feed",
                    "Attacker profiles updated for future correlation",
                ],
            },
        }

        return self._write_report(doc, rid, "ISO27001-A16", self._iso_text(doc))

    @staticmethod
    def _classify_incident(attack_types: list[str]) -> str:
        if any(t in attack_types for t in ("APT", "Infiltration", "ZeroDay")):
            return "A.16.1.5 — Response to information security incidents"
        if any(t in attack_types for t in ("DDoS", "DoS", "Ransomware")):
            return "A.16.1.4 — Assessment of and decision on information security events"
        return "A.16.1.2 — Reporting information security events"

    @staticmethod
    def _auto_root_cause(attack_types: list[str], stages: list[str]) -> str:
        if "Initial Access" in stages and "Lateral Movement" in stages:
            return "Attacker gained initial foothold and moved laterally — weak network segmentation suspected."
        if any(t in attack_types for t in ("BruteForce",)):
            return "Credential brute-force attack — lack of account lockout or MFA."
        if any(t in attack_types for t in ("SQLInjection", "XSS")):
            return "Web application vulnerability — insufficient input validation."
        if any(t in attack_types for t in ("DDoS", "DoS")):
            return "Volumetric denial-of-service — insufficient rate limiting / DDoS mitigation."
        return "Root cause under investigation — refer to forensic timeline."

    @staticmethod
    def _eradication_steps(attack_types: list[str]) -> list[str]:
        steps = [
            "Block all identified malicious IP ranges at perimeter firewall",
            "Reset passwords for all accounts accessed during the incident window",
        ]
        if any(t in attack_types for t in ("SQLInjection", "XSS", "CommandInject")):
            steps.append("Patch or WAF-protect the vulnerable web application endpoint")
        if "Bot" in attack_types:
            steps.append("Identify and clean all C2-beaconing endpoints")
        if "Heartbleed" in attack_types:
            steps.append("Patch OpenSSL and revoke/reissue TLS certificates")
        return steps

    @staticmethod
    def _corrective_actions(attack_types: list[str], soph: str) -> list[str]:
        actions = [
            "Update IDS/IPS signatures with patterns from this incident",
            "Review and tighten firewall and WAF rules",
        ]
        if soph in ("High", "APT"):
            actions.append("Engage threat-hunting team for deeper investigation")
            actions.append("Implement network micro-segmentation to limit lateral movement")
        if any(t in attack_types for t in ("BruteForce",)):
            actions.append("Enforce MFA on all externally-facing authentication endpoints")
        return actions

    @staticmethod
    def _iso_text(doc: dict) -> str:
        inc = doc["incident"]
        dc  = doc["detection_and_containment"]
        er  = doc["eradication_and_recovery"]
        ll  = doc["lessons_learned"]

        lines = [
            "ISO/IEC 27001 ANNEX A.16 — INFORMATION SECURITY INCIDENT REPORT",
            "=" * 60,
            f"Report ID      : {doc['report_id']}",
            f"Generated      : {doc['generated_at']}",
            f"Organisation   : {doc['organisation']}",
            f"Responder      : {doc['responder']}",
            "",
            "1. INCIDENT IDENTIFICATION",
            "-" * 60,
            f"Campaign ID    : {inc['campaign_id']}",
            f"Classification : {inc['classification']}",
            f"Severity       : {inc['severity']}",
            f"Period         : {inc['start_time']} to {inc['end_time']}",
            f"Duration       : {inc['duration_min']:.1f} min",
            f"Events         : {inc['event_count']}",
            f"Attack Types   : {', '.join(inc['attack_types']) or 'Unknown'}",
            f"Kill-Chain     : {' -> '.join(inc['kill_chain_stages']) or 'Single-stage'}",
            f"Sophistication : {inc['sophistication']}",
            "",
            "2. DETECTION AND CONTAINMENT",
            "-" * 60,
            f"Detected by    : {dc['detected_by']}",
            "Containment:",
        ]
        for a in dc["containment_actions"]:
            lines.append(f"  [X] {a}")
        lines += [
            "",
            "3. ERADICATION AND RECOVERY",
            "-" * 60,
            f"Root Cause     : {er['root_cause']}",
            f"Recovery       : {er['recovery_status']}",
            "Eradication:",
        ]
        for s in er["eradication"]:
            lines.append(f"  [ ] {s}")
        lines += [
            "",
            "4. LESSONS LEARNED",
            "-" * 60,
            "Corrective actions:",
        ]
        for a in ll["corrective_actions"]:
            lines.append(f"  [ ] {a}")
        lines.append("Preventive measures:")
        for m in ll["preventive_measures"]:
            lines.append(f"  [ ] {m}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

    def _write_report(
        self,
        doc:       dict,
        rid:       str,
        framework: str,
        text:      str,
    ) -> ComplianceReport:
        json_path = self._report_dir / f"{rid}.json"
        txt_path  = self._report_dir / f"{rid}.txt"

        try:
            json_path.write_text(
                json.dumps(doc, indent=2, default=str), encoding="utf-8"
            )
            txt_path.write_text(text, encoding="utf-8")
            logger.info("Compliance report written: %s (.json + .txt)", rid)
        except OSError as exc:
            logger.error("Report write failed: %s", exc)

        return ComplianceReport(
            report_id=rid,
            framework=framework,
            generated_at=doc["generated_at"],
            output_path=json_path,
            summary=text[:300] + "..." if len(text) > 300 else text,
        )
