"""
explainability/attack_narrator.py

Purpose: Convert raw SHAP values and model predictions into plain-English
         attack explanations that a SOC analyst can act on immediately.
         Each narrative names the top contributing features, describes what
         they indicate in network security terms, maps the decision to the
         MITRE ATT&CK technique, and recommends the next investigative step.

Inputs:  SHAPResult (from SHAPExplainer); detection event dict with
         attack_type, confidence, src_ip, and MITRE annotation fields.
Outputs: AttackNarration dataclass with headline, body, top_features list,
         and recommended_action string.

Usage:
    from explainability.attack_narrator import AttackNarrator
    narrator = AttackNarrator()
    narration = narrator.narrate(shap_result, event, sample_idx=0)
    print(narration.headline)
    print(narration.body)
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from config import MITRE_ATTACK_MAP, RESPONSE_MATRIX, SEVERITY_LEVELS
from explainability.shap_explainer import SHAPResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature → human-readable description mapping
# ---------------------------------------------------------------------------

_FEATURE_DESCRIPTIONS: dict[str, str] = {
    "bwd_packet_length_std":      "high variance in backward (server-to-client) packet sizes",
    "average_packet_size":        "unusually large average packet size",
    "packet_length_mean":         "elevated mean packet length",
    "packet_length_std":          "high packet-length variance",
    "max_packet_length":          "very large maximum packet size",
    "bytes_per_pkt":              "high bytes-per-packet ratio",
    "psh_flag_count":             "elevated TCP PSH flag usage (data-push heavy session)",
    "destination_port":           "suspicious destination port",
    "urg_flag_count":             "abnormal TCP URG (urgent) flag activity",
    "bwd_packet_length_mean":     "elevated mean backward packet length",
    "bwd_iat_std":                "irregular backward inter-arrival time",
    "avg_bwd_segment_size":       "large average backward TCP segment",
    "idle_mean":                  "abnormally long idle periods between flows",
    "bwd_packet_length_max":      "very large backward packet detected",
    "fwd_iat_max":                "long maximum forward inter-arrival gap",
    "syn_flag_count":             "high SYN flag count (possible SYN flood or port scan)",
    "fin_flag_count":             "abnormal FIN flag rate (abrupt connection teardown)",
    "rst_flag_count":             "high TCP RST count (connection resets / scan evidence)",
    "flow_duration":              "abnormal flow duration",
    "total_fwd_packets":          "high number of forward packets (data exfiltration candidate)",
    "total_backward_packets":     "high backward packet count",
    "flow_bytes_per_s":           "extreme byte rate",
    "flow_packets_per_s":         "extreme packet rate (volumetric attack candidate)",
    "init_win_bytes_forward":     "suspicious initial TCP window size",
    "init_win_bytes_backward":    "suspicious server-side TCP window size",
    "fwd_psh_flags":              "forward PSH flags set (data push from client)",
    "bwd_psh_flags":              "backward PSH flags set (data push from server)",
    "act_data_pkt_fwd":           "high actual data packet count in forward direction",
    "fwd_packet_length_max":      "large forward packet detected",
    "subflow_fwd_bytes":          "high subflow forward byte count",
}

# Attack-type → security context description
_ATTACK_CONTEXT: dict[str, str] = {
    "DDoS":         "a Distributed Denial-of-Service flood targeting network availability",
    "DoS":          "a Denial-of-Service attack exhausting server resources",
    "PortScan":     "network reconnaissance / port enumeration activity",
    "BruteForce":   "credential brute-forcing or password-spraying",
    "SQLInjection": "SQL injection targeting database access",
    "XSS":          "cross-site scripting payload injection",
    "Bot":          "botnet C2 communication or automated bot behaviour",
    "Infiltration": "lateral movement and internal reconnaissance",
    "Heartbleed":   "TLS Heartbleed memory-leak exploitation",
    "ZeroDay":      "an unknown/zero-day attack pattern flagged by anomaly detection",
    "APT":          "advanced persistent threat behaviour",
    "Phishing":     "phishing or malicious URL activity",
    "CommandInject": "OS command injection via web input",
    "PathTraversal": "directory traversal attack",
    "Ransomware":    "ransomware file-encryption behaviour",
}

# Attack-type → recommended first response action
_RECOMMENDED_ACTIONS: dict[str, str] = {
    "DDoS":          "Activate rate-limiting and upstream DDoS mitigation; block source ASN if volumetric.",
    "DoS":           "Rate-limit source IP; check server load and apply connection throttle.",
    "PortScan":      "Block source IP for 24 h; check whether scan targeted internal services.",
    "BruteForce":    "Block source IP for 1 h; force password reset on targeted accounts; enforce MFA.",
    "SQLInjection":  "Block request; review database query logs; patch vulnerable endpoint.",
    "XSS":           "Block request; audit application input-validation; deploy CSP header.",
    "Bot":           "Block source IP and C2 domain; check for other infected hosts beaconing out.",
    "Infiltration":  "CRITICAL — isolate affected network segment; initiate full forensic investigation.",
    "Heartbleed":    "CRITICAL — patch OpenSSL; revoke and reissue all TLS certificates immediately.",
    "ZeroDay":       "CRITICAL — quarantine source; capture all traffic; trigger adaptive retrain.",
    "APT":           "CRITICAL — engage threat-hunting team; full network isolation; evidence preservation.",
    "Phishing":      "Block malicious domain; notify affected users; scan for credential reuse.",
    "CommandInject": "Block request; audit web application logs for prior exploitation.",
    "PathTraversal": "Block request; audit file-access logs; restrict web-server directory permissions.",
}


def _feature_description(name: str, value: float, contribution: float) -> str:
    desc    = _FEATURE_DESCRIPTIONS.get(name, f"anomalous {name.replace('_', ' ')}")
    sign    = "elevated" if contribution > 0 else "unusually low"
    return f"{desc} (value={value:.2f}, contribution={contribution:+.3f})"


@dataclass
class AttackNarration:
    headline:          str
    body:              str
    top_features:      list[tuple[str, float, str]]   # (name, shap_val, description)
    attack_type:       str
    confidence:        float
    mitre_tactic:      str
    mitre_technique:   str
    recommended_action: str
    severity:          str


class AttackNarrator:
    """
    SHAP-driven plain-English attack narration engine.

    Combines SHAP values with detection event metadata to produce structured
    narratives readable by SOC analysts without ML background.

    narrate()      — explain one sample from a SHAPResult
    narrate_batch() — produce a summary narrative across all explained samples

    Parameters: none
    """

    def __init__(self) -> None:
        logger.info("AttackNarrator ready")

    # ------------------------------------------------------------------
    # Single-sample narration
    # ------------------------------------------------------------------

    def narrate(
        self,
        result:      SHAPResult,
        event:       dict,
        sample_idx:  int = 0,
        top_n:       int = 5,
    ) -> AttackNarration:
        """
        Generate a natural-language explanation for one classified flow.

        Inputs:
            result     — SHAPResult from SHAPExplainer.explain()
            event      — detection event dict (attack_type, confidence, src_ip, …)
            sample_idx — which row in result to explain (default 0)
            top_n      — number of top features to include in narrative
        Outputs: AttackNarration dataclass
        """
        attack_type = event.get("attack_type", "Unknown")
        confidence  = float(event.get("confidence", 0.0))
        src_ip      = event.get("src_ip", "Unknown")
        tactic      = event.get("mitre_tactic",       "") or \
                      MITRE_ATTACK_MAP.get(attack_type, {}).get("tactic", "Unknown")
        technique   = event.get("mitre_technique_id", "") or \
                      MITRE_ATTACK_MAP.get(attack_type, {}).get("technique", "T0000")
        tech_name   = MITRE_ATTACK_MAP.get(attack_type, {}).get("name", "Unknown technique")

        # Guard sample index
        n_rows = result.shap_values.shape[0]
        idx    = min(sample_idx, n_rows - 1)

        row_shap = result.shap_values[idx]
        row_data = result.X_explained.iloc[idx] if idx < len(result.X_explained) else None

        # Rank features by absolute SHAP contribution
        abs_vals = np.abs(row_shap)
        ranked   = sorted(
            enumerate(zip(result.feature_names, row_shap, abs_vals)),
            key=lambda x: x[1][2], reverse=True,
        )[:top_n]

        top_features: list[tuple[str, float, str]] = []
        feature_lines: list[str] = []
        for rank, (feat_idx, (fname, shap_val, _)) in enumerate(ranked, 1):
            val  = float(row_data.iloc[feat_idx]) if row_data is not None else 0.0
            desc = _feature_description(fname, val, shap_val)
            top_features.append((fname, round(float(shap_val), 4), desc))
            feature_lines.append(f"  {rank}. {fname}: {desc}")

        severity = self._severity_for(attack_type)
        context  = _ATTACK_CONTEXT.get(attack_type, f"a {attack_type} attack")
        action   = _RECOMMENDED_ACTIONS.get(attack_type,
                   "Investigate the source IP and review related network logs.")

        # Headline
        conf_pct = round(confidence * 100, 1)
        headline = (
            f"[{severity}] {attack_type} detected from {src_ip} "
            f"with {conf_pct}% confidence"
        )

        # Body
        body_lines = [
            f"SENTINEL IPS classified traffic from {src_ip} as {context}.",
            f"Model confidence: {conf_pct}%  |  Base rate: {result.base_value:.3f}",
            f"MITRE ATT&CK: {tactic} / {technique} — {tech_name}",
            "",
            "KEY DECISION FACTORS (top contributing features):",
        ]
        body_lines.extend(feature_lines)
        body_lines += [
            "",
            f"RECOMMENDED ACTION: {action}",
        ]

        return AttackNarration(
            headline=headline,
            body="\n".join(body_lines),
            top_features=top_features,
            attack_type=attack_type,
            confidence=confidence,
            mitre_tactic=tactic,
            mitre_technique=technique,
            recommended_action=action,
            severity=severity,
        )

    # ------------------------------------------------------------------
    # Batch summary narration
    # ------------------------------------------------------------------

    def narrate_batch(
        self,
        result:      SHAPResult,
        attack_type: str = "Unknown",
        top_n:       int = 10,
    ) -> str:
        """
        Generate a population-level summary narrative for all explained samples.

        Reports the globally most important features across the full explained
        set rather than explaining a single sample.

        Inputs:
            result      — SHAPResult covering multiple samples
            attack_type — attack class label for this explanation run
            top_n       — number of features to list
        Outputs: formatted multi-line summary string
        """
        mean_abs = np.abs(result.shap_values).mean(axis=0)
        total    = mean_abs.sum() or 1.0
        ranked   = sorted(
            zip(result.feature_names, mean_abs),
            key=lambda x: x[1], reverse=True,
        )[:top_n]

        context = _ATTACK_CONTEXT.get(attack_type, f"a {attack_type} attack")
        lines   = [
            f"GLOBAL SHAP EXPLANATION — {attack_type}",
            "=" * 55,
            f"Samples explained : {result.shap_values.shape[0]}",
            f"Attack context    : {context}",
            f"Explainer         : {result.explainer_type}",
            "",
            "TOP FEATURES BY MEAN |SHAP|:",
        ]

        for rank, (fname, importance) in enumerate(ranked, 1):
            pct  = round(importance / total * 100, 2)
            desc = _FEATURE_DESCRIPTIONS.get(fname, fname.replace("_", " "))
            lines.append(f"  {rank:2d}. {fname:<35} {pct:6.2f}%  ({desc})")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_for(attack_type: str) -> str:
        for level, attacks in SEVERITY_LEVELS.items():
            if attack_type in attacks:
                return level
        return "MEDIUM"
