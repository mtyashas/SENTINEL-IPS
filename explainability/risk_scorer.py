"""
explainability/risk_scorer.py

Purpose: Compute a composite threat risk score (0–100) for each detection event
         by fusing six independent signal dimensions: model confidence, attack
         severity, MITRE kill-chain advancement, IP reputation, attacker
         sophistication, and recurrence. The resulting score drives alert
         prioritisation and dashboard colouring so analysts focus on the
         highest-risk events first.

Inputs:  Detection event dict; optional IPReputationResult; optional
         AttackerProfile from ThreatActorProfiler.
Outputs: RiskScore dataclass with composite score, per-dimension breakdown,
         and a human-readable risk label.

Usage:
    from explainability.risk_scorer import RiskScorer
    scorer = RiskScorer()
    risk   = scorer.score(event, ip_rep=ip_result, profile=attacker_profile)
    print(risk.score, risk.label, risk.breakdown)
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from config import MITRE_ATTACK_MAP, SEVERITY_LEVELS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring weights — must sum to 1.0
# ---------------------------------------------------------------------------

_WEIGHTS = {
    "confidence":    0.25,   # model certainty
    "severity":      0.25,   # static attack-type severity
    "kill_chain":    0.20,   # how far into the kill chain
    "ip_reputation": 0.15,   # threat-intel IP score
    "sophistication": 0.10,  # attacker actor class
    "recurrence":    0.05,   # repeat attacker bonus
}

assert abs(sum(_WEIGHTS.values()) - 1.0) < 1e-9, "Weights must sum to 1.0"

# Severity → base score component
_SEVERITY_SCORES: dict[str, float] = {
    "CRITICAL": 100.0,
    "HIGH":     75.0,
    "MEDIUM":   50.0,
    "LOW":      25.0,
    "INFO":     10.0,
}

# MITRE tactic → kill-chain advancement score (later = more dangerous)
_TACTIC_SCORES: dict[str, float] = {
    "Reconnaissance":       10.0,
    "Resource Development": 15.0,
    "Initial Access":       30.0,
    "Execution":            45.0,
    "Persistence":          55.0,
    "Privilege Escalation": 65.0,
    "Defense Evasion":      70.0,
    "Credential Access":    72.0,
    "Discovery":            40.0,
    "Lateral Movement":     80.0,
    "Collection":           75.0,
    "Command and Control":  85.0,
    "Exfiltration":         90.0,
    "Impact":               95.0,
    "Multiple":             85.0,
    "Unknown":              20.0,
}

# Actor class → sophistication score
_SOPHISTICATION_SCORES: dict[str, float] = {
    "APT":         100.0,
    "Organised":   65.0,
    "ScriptKiddie": 20.0,
    "Insider":     80.0,
    "Unknown":     30.0,
}

_RISK_LABELS: list[tuple[float, str]] = [
    (90, "CRITICAL"),
    (70, "HIGH"),
    (45, "MEDIUM"),
    (20, "LOW"),
    (0,  "INFO"),
]


@dataclass
class RiskScore:
    score:      float                        # 0.0 – 100.0
    label:      str                          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    breakdown:  dict[str, float] = field(default_factory=dict)
    attack_type: str  = ""
    src_ip:     str   = ""
    explanation: str  = ""


def _label_for(score: float) -> str:
    for threshold, label in _RISK_LABELS:
        if score >= threshold:
            return label
    return "INFO"


def _severity_for(attack_type: str) -> str:
    for level, attacks in SEVERITY_LEVELS.items():
        if attack_type in attacks:
            return level
    return "MEDIUM"


class RiskScorer:
    """
    Composite risk scorer that fuses six independent signal dimensions.

    Score formula (each dimension scaled to 0–100 then weighted):
      composite = sum(weight_i × component_i)   for i in dimensions

    Dimensions:
      confidence    — model output probability × 100
      severity      — static lookup from SEVERITY_LEVELS
      kill_chain    — tactic advancement score from _TACTIC_SCORES
      ip_reputation — IPReputationScorer score (already 0–100)
      sophistication — actor class from ThreatActorProfiler
      recurrence    — hit_count from AttackerProfile (capped at 100)

    Parameters: none
    """

    def __init__(self) -> None:
        logger.info("RiskScorer ready — %d dimensions, weights=%s",
                    len(_WEIGHTS), _WEIGHTS)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(
        self,
        event:      dict,
        ip_rep=None,      # Optional[IPReputationResult]
        profile=None,     # Optional[AttackerProfile]
    ) -> RiskScore:
        """
        Compute a composite risk score for one detection event.

        Inputs:
            event   — detection dict (attack_type, confidence, src_ip,
                       mitre_tactic, mitre_severity)
            ip_rep  — IPReputationResult from IPReputationScorer (optional)
            profile — AttackerProfile from ThreatActorProfiler (optional)
        Outputs: RiskScore
        """
        attack_type = event.get("attack_type", "Unknown")
        src_ip      = event.get("src_ip", "Unknown")

        # --- Dimension 1: confidence ---
        raw_conf   = float(event.get("confidence", 0.5))
        conf_score = min(raw_conf * 100.0, 100.0)

        # --- Dimension 2: severity ---
        severity_str  = (
            event.get("mitre_severity")
            or event.get("severity")
            or _severity_for(attack_type)
        )
        sev_score = _SEVERITY_SCORES.get(severity_str, 50.0)

        # --- Dimension 3: kill-chain advancement ---
        tactic    = (
            event.get("mitre_tactic")
            or MITRE_ATTACK_MAP.get(attack_type, {}).get("tactic", "Unknown")
        )
        kc_score  = _TACTIC_SCORES.get(tactic, 20.0)

        # --- Dimension 4: IP reputation ---
        if ip_rep is not None:
            ip_score = float(getattr(ip_rep, "score", 0))
        else:
            ip_score = 0.0

        # --- Dimension 5: actor sophistication ---
        if profile is not None:
            actor_class = getattr(profile, "actor_class", "Unknown")
        else:
            actor_class = "Unknown"
        soph_score = _SOPHISTICATION_SCORES.get(actor_class, 30.0)

        # --- Dimension 6: recurrence ---
        if profile is not None:
            hit_count  = int(getattr(profile, "event_count", 1))
            recur_score = min(hit_count * 5.0, 100.0)
        else:
            recur_score = 0.0

        breakdown = {
            "confidence":    round(conf_score,  2),
            "severity":      round(sev_score,   2),
            "kill_chain":    round(kc_score,    2),
            "ip_reputation": round(ip_score,    2),
            "sophistication": round(soph_score, 2),
            "recurrence":    round(recur_score, 2),
        }

        composite = sum(
            _WEIGHTS[dim] * val for dim, val in breakdown.items()
        )
        composite = round(min(composite, 100.0), 2)
        label     = _label_for(composite)

        explanation = self._explain(composite, label, breakdown, attack_type, tactic, actor_class)

        logger.debug(
            "Risk score for %s (%s): %.1f [%s] — %s",
            src_ip, attack_type, composite, label,
            {k: v for k, v in breakdown.items()},
        )

        return RiskScore(
            score=composite,
            label=label,
            breakdown=breakdown,
            attack_type=attack_type,
            src_ip=src_ip,
            explanation=explanation,
        )

    def score_batch(
        self,
        events:  list[dict],
        ip_reps: Optional[list] = None,
        profiles: Optional[list] = None,
    ) -> list[RiskScore]:
        """
        Score a list of detection events.

        Inputs:
            events   — list of event dicts
            ip_reps  — parallel list of IPReputationResult (None entries allowed)
            profiles — parallel list of AttackerProfile (None entries allowed)
        Outputs: list of RiskScore in the same order, sorted by score descending
        """
        scores: list[RiskScore] = []
        for i, ev in enumerate(events):
            ip_rep  = ip_reps[i]  if ip_reps  and i < len(ip_reps)  else None
            profile = profiles[i] if profiles and i < len(profiles) else None
            scores.append(self.score(ev, ip_rep=ip_rep, profile=profile))
        return sorted(scores, key=lambda r: r.score, reverse=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _explain(
        composite:  float,
        label:      str,
        breakdown:  dict[str, float],
        attack_type: str,
        tactic:     str,
        actor_class: str,
    ) -> str:
        top_dim = max(breakdown, key=lambda k: _WEIGHTS[k] * breakdown[k])
        top_val = breakdown[top_dim]
        return (
            f"Risk {label} ({composite:.1f}/100): "
            f"primary driver is {top_dim} ({top_val:.1f}) — "
            f"{attack_type} attack via {tactic} by {actor_class} actor."
        )
