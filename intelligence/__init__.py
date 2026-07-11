"""intelligence — SENTINEL IPS v2.0 threat intelligence layer."""

from intelligence.threat_feeds import ThreatFeedAggregator, ThreatResult
from intelligence.ip_reputation import IPReputationScorer, IPReputationResult
from intelligence.domain_reputation import DomainReputationChecker, DomainReputationResult
from intelligence.honeypot import HoneypotMonitor, HoneypotEvent

__all__ = [
    "ThreatFeedAggregator",
    "ThreatResult",
    "IPReputationScorer",
    "IPReputationResult",
    "DomainReputationChecker",
    "DomainReputationResult",
    "HoneypotMonitor",
    "HoneypotEvent",
]
