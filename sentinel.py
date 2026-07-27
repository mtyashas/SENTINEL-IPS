"""
sentinel.py

Purpose: SENTINEL IPS v2.0 — main runtime entry point.
         Orchestrates all 10 operational modules in a unified processing loop:

         Layer 1  — ML detection (BenchmarkIDS / LightweightIDS)
         Layer 2  — Signature detection (SQL injection, XSS, command injection)
         Layer 3  — Anomaly detection (IsolationForest zero-day)
         Intel    — IP reputation, threat feeds, domain reputation
         Attribution — Geolocation, MITRE ATT&CK mapping, threat profiling
         Response — Rate limiting, IP blocking, session termination, alerting
         Adaptive — Mistake collection, adaptive retraining, zero-day mining
         Forensics — Packet logging, timeline reconstruction, compliance reports
         Explainability — SHAP, attack narration, risk scoring
         Dashboard — LiveMonitor + AttackMap data feeds

         Two operating modes:
           simulate — replay CSV flow data through the full pipeline
           live     — real-time capture via Scapy (requires root / WinPcap)

Usage:
    python sentinel.py simulate --model models/benchmarkids_binary.pkl
    python sentinel.py simulate --data datasets/CIC-IDS-2017/**/*.csv --sample 0.001
    python sentinel.py live --interface eth0
    python sentinel.py simulate --help
"""

import argparse
import gc
import logging
import sys
import time
from pathlib import Path
from typing import Optional

# Ensure project root is on sys.path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ---------------------------------------------------------------------------
# Logging (must be configured before any module imports)
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(_ROOT / "logs" / "sentinel.log",
                            mode="a", encoding="utf-8"),
    ],
)
logger = logging.getLogger("sentinel")

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------

import joblib
import numpy as np
import pandas as pd

from config import (
    ATTACK_CLASSES,
    BINARY_LABEL_COL,
    CHUNK_SIZE,
    CONFIDENCE_THRESHOLD,
    DATA_2017,
    ENGINEERED_FEATURES,
    FLOW_GC_INTERVAL_S,
    LIVE_BPF_FILTER,
    LIVE_INTERFACE_DEFAULT,
    MITRE_ATTACK_MAP,
    MODEL_DIR,
    MULTICLASS_LABEL_COL,
    REALTIME_CHUNK_SIZE,
    REPORT_DIR,
    RESPONSE_MATRIX,
    SEVERITY_LEVELS,
)

# Detection
from detection.layer1_ml import MLDetectionLayer
from detection.layer2_signatures import SignatureDetector
from detection.layer3_anomaly import AnomalyDetector

# Intelligence
from intelligence.ip_reputation import IPReputationScorer
from intelligence.threat_feeds import ThreatFeedAggregator

# Attribution
from attribution.geolocator import Geolocator
from attribution.mitre_mapper import MITREMapper
from attribution.threat_profiler import ThreatActorProfiler

# Response
from response.alert_dispatcher import AlertDispatcher
from response.ip_blacklister import IPBlacklister
from response.rate_limiter import RateLimiter

# Adaptive
from adaptive.mistake_collector import MistakeCollector
from adaptive.zero_day_miner import ZeroDayMiner

# Forensics
from forensics.packet_logger import PacketLogger
from forensics.timeline_builder import TimelineBuilder

# Explainability
from explainability.attack_narrator import AttackNarrator
from explainability.risk_scorer import RiskScorer

# Evaluation
from evaluation.metrics import IDSEvaluator

# Dashboard
from dashboard.attack_map import AttackMap
from dashboard.live_monitor import LiveMonitor

# Preprocessing (for simulate mode)
from core.features import NetworkFeatureEngineer, get_feature_matrix
from core.preprocessing import load_full_dataset

# Flow assembly (for live mode)
from core.flow_collector import FlowCollector


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EXPLAIN_EVERY    = 500    # run SHAP narration every N detections
_ZD_MINE_EVERY    = 2000   # run zero-day miner every N flows
_RETRAIN_CHECK_S  = 3600   # check adaptive retrain every hour
_LOG_INTERVAL     = 10_000 # progress log every N flows

# RESPONSE_MATRIX action string -> block duration (seconds; 0 = permanent)
_BLOCK_ACTION_DURATIONS = {
    "ip_block_1h":  3600,
    "ip_block_24h": 86400,
    "ip_block":     3600,
}


# ---------------------------------------------------------------------------
# SENTINEL engine
# ---------------------------------------------------------------------------

class SentinelIPS:
    """
    SENTINEL IPS v2.0 — unified runtime engine.

    Initialises all modules once and exposes process_chunk() to run any
    DataFrame of flow records through the complete 10-layer pipeline.

    Parameters:
        model_path     — path to serialised BenchmarkIDS binary pkl
        lite_path      — path to serialised LightweightIDS pkl (optional)
        use_lite       — use lightweight model for throughput-critical paths
        enforce_blocks — enable OS-level IP blocking (requires elevated privileges)
    """

    def __init__(
        self,
        model_path:     Optional[str] = None,
        lite_path:      Optional[str] = None,
        use_lite:       bool = False,
        enforce_blocks: bool = False,
    ) -> None:

        logger.info("Initialising SENTINEL IPS v2.0...")
        t0 = time.monotonic()

        # --- Layer 1 ---
        self._layer1: Optional[MLDetectionLayer] = None
        if model_path and Path(model_path).exists():
            feat_path = str(Path(model_path).parent /
                            (Path(model_path).stem + "_feature_cols.pkl"))
            try:
                self._layer1 = MLDetectionLayer(
                    model_path=model_path,
                    feat_cols_path=feat_path,
                )
                logger.info("Layer1 ML loaded: %s", model_path)
            except Exception as exc:
                logger.warning("Layer1 ML init failed: %s", exc)
        else:
            logger.warning(
                "No ML model path provided or file missing — "
                "Layer 1 (ML detection) disabled. Run train.py first."
            )

        self._use_lite  = use_lite
        self._lite_path = lite_path

        # --- Layer 2: signatures ---
        self._sig = SignatureDetector()
        logger.info("Layer2 signatures ready")

        # --- Layer 3: anomaly ---
        self._anomaly = AnomalyDetector(contamination=0.005)
        self._anomaly_fitted = False
        self._anomaly_baseline_buffer: list = []

        # --- Intelligence ---
        self._ip_rep    = IPReputationScorer()
        self._threat    = ThreatFeedAggregator()
        logger.info("Intelligence layer ready")

        # --- Attribution ---
        self._geo       = Geolocator()
        self._mitre     = MITREMapper()
        self._profiler  = ThreatActorProfiler()
        logger.info("Attribution layer ready")

        # --- Response ---
        self._blacklist  = IPBlacklister(enforce_os_firewall=enforce_blocks)
        self._rate       = RateLimiter()
        self._dispatcher = AlertDispatcher()
        logger.info("Response layer ready")

        # --- Adaptive ---
        self._mistakes  = MistakeCollector()
        self._zd_miner  = ZeroDayMiner()
        logger.info("Adaptive layer ready")

        # --- Forensics ---
        self._pkt_logger  = PacketLogger()
        self._timeline    = TimelineBuilder()
        logger.info("Forensics layer ready")

        # --- Explainability ---
        self._narrator  = AttackNarrator()
        self._risk      = RiskScorer()
        self._shap      = None   # built lazily after first fit
        logger.info("Explainability layer ready")

        # --- Dashboard singletons ---
        self._monitor   = LiveMonitor()
        self._amap      = AttackMap()

        # --- Internal counters ---
        self._n_flows         = 0
        self._n_attacks       = 0
        self._n_explained     = 0
        self._events_buffer:  list[dict] = []
        self._session_start   = time.monotonic()
        self._last_retrain_t  = time.monotonic()

        logger.info("SENTINEL IPS v2.0 ready in %.1fs", time.monotonic() - t0)

    # ------------------------------------------------------------------
    # Public accessors (for dashboard/app.py integration)
    # ------------------------------------------------------------------

    @property
    def monitor(self) -> LiveMonitor:
        return self._monitor

    @property
    def attack_map(self) -> AttackMap:
        return self._amap

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------

    def process_chunk(self, chunk: pd.DataFrame) -> pd.DataFrame:
        """
        Run one DataFrame chunk through all 10 pipeline layers.

        Inputs:  chunk — raw or preprocessed flow DataFrame
        Outputs: chunk annotated with pred_binary, confidence, attack_type,
                 risk_score, action columns
        """
        if chunk.empty:
            return chunk

        # --- Layer 1: ML inference ---
        chunk = self._run_layer1(chunk)

        # --- Layer 3: anomaly detection (fit on first non-trivial chunk) ---
        chunk = self._run_anomaly(chunk)

        # --- Process only detected attacks through downstream layers ---
        attack_mask = chunk.get("pred_binary", pd.Series(0, index=chunk.index)) == 1
        if not attack_mask.any():
            self._n_flows += len(chunk)
            self._monitor.record_throughput(
                self._estimate_fps(len(chunk)))
            return chunk

        attack_rows = chunk[attack_mask].copy()
        self._process_attacks(attack_rows)

        self._n_flows   += len(chunk)
        self._n_attacks += int(attack_mask.sum())
        self._monitor.record_throughput(self._estimate_fps(len(chunk)))

        # --- Periodic zero-day mining ---
        if self._n_flows % _ZD_MINE_EVERY < len(chunk):
            self._run_zd_mining(chunk)

        # --- Periodic progress log ---
        if self._n_flows % _LOG_INTERVAL < len(chunk):
            elapsed = time.monotonic() - self._session_start
            logger.info(
                "[%s] flows=%d  attacks=%d  fps=%.0f",
                time.strftime("%H:%M:%S"),
                self._n_flows, self._n_attacks,
                self._n_flows / max(elapsed, 1),
            )

        return chunk

    # ------------------------------------------------------------------
    # Per-attack event pipeline
    # ------------------------------------------------------------------

    def _process_attacks(self, attacks: pd.DataFrame) -> None:
        for _, row in attacks.iterrows():
            event = self._build_event(row)
            if event is None:
                continue

            # Intel
            event = self._run_intel(event)

            # Attribution
            event = self._run_attribution(event)

            # Risk scoring
            event = self._run_risk(event)

            # Response
            self._run_response(event)

            logger.info(
                "DETECTION src=%s dst_port=%d attack=%s confidence=%.2f "
                "severity=%s mitre=%s/%s action=%s",
                event["src_ip"], event["dst_port"], event["attack_type"],
                event["confidence"], event["severity"],
                event.get("mitre_technique", "T0000"),
                event.get("mitre_tactic", "Unknown"), event["action"],
            )

            # Forensics
            self._pkt_logger.log_event(event)
            self._events_buffer.append(event)

            # SHAP narration (sampled)
            if self._n_attacks % _EXPLAIN_EVERY == 0:
                self._run_explanation(attacks.head(1))

            # Dashboard feed
            self._monitor.push_event(event)
            self._amap.ingest(event)

    # ------------------------------------------------------------------
    # Layer 1: ML inference
    # ------------------------------------------------------------------

    def _run_layer1(self, chunk: pd.DataFrame) -> pd.DataFrame:
        if self._layer1 is None:
            chunk["pred_binary"] = 0
            chunk["confidence"]  = 0.0
            return chunk
        try:
            result = self._layer1.predict_chunk(chunk)
            return result
        except Exception as exc:
            logger.debug("Layer1 predict_chunk error: %s", exc)
            chunk["pred_binary"] = 0
            chunk["confidence"]  = 0.0
            return chunk

    # ------------------------------------------------------------------
    # Layer 3: anomaly detection
    # ------------------------------------------------------------------

    def _run_anomaly(self, chunk: pd.DataFrame) -> pd.DataFrame:
        try:
            num_cols = chunk.select_dtypes(include=[np.number]).columns.tolist()
            label_cols = {"pred_binary", "confidence", "anomaly_score",
                          "anomaly_detected", BINARY_LABEL_COL, MULTICLASS_LABEL_COL}
            feat_cols = [c for c in num_cols if c not in label_cols]
            if not feat_cols:
                return chunk

            X_num = chunk[feat_cols].replace([np.inf, -np.inf], np.nan).fillna(0)

            if not self._anomaly_fitted:
                # Fit only on flows Layer 1 already called benign, accumulated
                # across calls until there's enough to fit on -- not on
                # whatever's in the first single chunk that happens to cross
                # 100 rows. A burst/flood produces large chunks fast, so
                # fitting on raw chunk contents risked baselining the "normal"
                # distribution on attack-heavy data, making genuinely benign
                # traffic look anomalous by comparison afterward (M5 finding,
                # docs/SESSION_LEDGER.md 2026-07-27).
                benign_mask = chunk.get("pred_binary", pd.Series(0, index=chunk.index)) == 0
                if benign_mask.any():
                    self._anomaly_baseline_buffer.append(X_num[benign_mask])
                buffered = sum(len(b) for b in self._anomaly_baseline_buffer)
                if buffered >= 100:
                    baseline = pd.concat(self._anomaly_baseline_buffer, ignore_index=True)
                    self._anomaly.fit(baseline)
                    self._anomaly_fitted = True
                    self._anomaly_baseline_buffer = []

            if self._anomaly_fitted:
                result_df = self._anomaly.predict(X_num)
                if "anomaly_score" in result_df.columns:
                    chunk = chunk.copy()
                    chunk["anomaly_score"]    = result_df["anomaly_score"].values
                    chunk["anomaly_detected"] = result_df["anomaly_detected"].values
                    # Promote anomaly detections to attack if ML missed them
                    anomaly_flag = chunk["anomaly_detected"].astype(bool)
                    if "pred_binary" in chunk.columns:
                        chunk.loc[anomaly_flag, "pred_binary"] = 1
                    else:
                        chunk["pred_binary"] = anomaly_flag.astype(int)
        except Exception as exc:
            logger.debug("Anomaly detection error: %s", exc)
        return chunk

    # ------------------------------------------------------------------
    # Event construction
    # ------------------------------------------------------------------

    def _build_event(self, row: pd.Series) -> Optional[dict]:
        try:
            attack_type = str(row.get("attack_class", "Unknown"))
            if attack_type in ("0", "BENIGN", "nan", ""):
                # Use anomaly score to guess ZeroDay
                if float(row.get("anomaly_score", 0)) >= 0.2:
                    attack_type = "ZeroDay"
                else:
                    attack_type = "Unknown"

            return {
                "attack_type": attack_type,
                "src_ip":      str(row.get("src_ip", row.get("source_ip", "0.0.0.0"))),
                "dst_ip":      str(row.get("dst_ip", row.get("destination_ip", "0.0.0.0"))),
                "src_port":    int(row.get("src_port", 0)),
                "dst_port":    int(row.get("destination_port", row.get("dst_port", 0))),
                "confidence":  float(row.get("confidence", 0.5)),
                "anomaly_score": float(row.get("anomaly_score", 0.0)),
                "severity":    self._severity_for(attack_type),
                "timestamp":   time.time(),
                "flow_bytes":  float(row.get("flow_bytes_per_s", 0)),
            }
        except Exception as exc:
            logger.debug("Event build error: %s", exc)
            return None

    @staticmethod
    def _severity_for(attack_type: str) -> str:
        for level, attacks in SEVERITY_LEVELS.items():
            if attack_type in attacks:
                return level
        return "MEDIUM"

    # ------------------------------------------------------------------
    # Intelligence
    # ------------------------------------------------------------------

    def _run_intel(self, event: dict) -> dict:
        src_ip = event["src_ip"]
        try:
            ip_rep = self._ip_rep.score(src_ip)
            event["ip_reputation"]    = ip_rep.score
            event["ip_is_malicious"]  = ip_rep.is_malicious
            event["ip_rep_sources"]   = ip_rep.sources
        except Exception:
            event["ip_reputation"] = 0.0
            event["ip_is_malicious"] = False
        return event

    # ------------------------------------------------------------------
    # Attribution
    # ------------------------------------------------------------------

    def _run_attribution(self, event: dict) -> dict:
        src_ip = event["src_ip"]

        # Geolocation
        try:
            geo = self._geo.locate(src_ip)
            event.update({
                "country":      geo.country,
                "country_code": geo.country_code,
                "city":         geo.city,
                "lat":          geo.lat,
                "lon":          geo.lon,
            })
        except Exception:
            event.update({"country": "Unknown", "country_code": "", "city": "",
                           "lat": 0.0, "lon": 0.0})

        # MITRE mapping
        try:
            annotated = self._mitre.annotate_event(event)
            event["mitre_tactic"]     = annotated.get("mitre_tactic",     "Unknown")
            event["mitre_technique"]  = annotated.get("mitre_technique",  "T0000")
            event["mitre_technique_name"] = annotated.get("mitre_technique_name", "")
        except Exception:
            event["mitre_tactic"] = MITRE_ATTACK_MAP.get(
                event["attack_type"], {}).get("tactic", "Unknown")

        # Threat actor profiling
        try:
            profile = self._profiler.ingest(
                event,
                geo_country=event.get("country", ""),
                geo_city=event.get("city", ""),
                is_vpn=False,
            )
            event["actor_class"]       = profile.actor_class
            event["sophistication"]    = profile.sophistication_score
        except Exception:
            event["actor_class"]    = "Unknown"
            event["sophistication"] = 30.0

        return event

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _run_risk(self, event: dict) -> dict:
        try:
            risk = self._risk.score(event)
            event["risk_score"] = risk.score
            event["risk_label"] = risk.label
            event["risk_explanation"] = risk.explanation
        except Exception:
            event["risk_score"] = 50.0
            event["risk_label"] = "MEDIUM"
        return event

    # ------------------------------------------------------------------
    # Response
    # ------------------------------------------------------------------

    def _run_response(self, event: dict) -> None:
        src_ip     = event["src_ip"]
        attack     = event["attack_type"]
        severity   = event["severity"]
        confidence = event["confidence"]

        actions = RESPONSE_MATRIX.get(attack, ["log"])
        event["action"] = ", ".join(actions[:2])

        # Rate limiting always applied first
        try:
            rl = self._rate.check(src_ip, attack_type=attack)
            if rl.throttled:
                logger.debug("Rate-limited %s (%s)", src_ip, attack)
        except Exception:
            pass

        # IP blocking for HIGH/CRITICAL
        blocked = False
        if severity in ("HIGH", "CRITICAL") and confidence >= 0.70:
            try:
                duration = 3600 if severity == "HIGH" else 0   # 0 = permanent
                self._blacklist.block(src_ip, duration_s=duration,
                                      reason=f"{attack} ({severity})")
                blocked = True
            except Exception as exc:
                logger.debug("Block failed: %s", exc)

        # RESPONSE_MATRIX assigns some MEDIUM/LOW-severity attacks their own
        # ip_block_* action independent of severity (e.g. BruteForce ->
        # ip_block_1h, PortScan -> ip_block_24h) -- honour it even though
        # severity alone didn't trigger a block above. Previously `actions`
        # was computed but only used for the cosmetic event["action"] string,
        # so these documented blocks were silently unreachable.
        if not blocked and confidence >= 0.70:
            block_action = next((a for a in actions if a in _BLOCK_ACTION_DURATIONS), None)
            if block_action:
                try:
                    self._blacklist.block(src_ip, duration_s=_BLOCK_ACTION_DURATIONS[block_action],
                                          reason=f"{attack} ({severity})")
                except Exception as exc:
                    logger.debug("Block failed: %s", exc)

        # Alert dispatch (non-blocking)
        try:
            self._dispatcher.dispatch({
                "attack_type": attack,
                "severity":    severity,
                "src_ip":      src_ip,
                "detail":      event.get("risk_explanation", ""),
                "confidence":  confidence,
            })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # SHAP narration (sampled)
    # ------------------------------------------------------------------

    def _run_explanation(self, sample_df: pd.DataFrame) -> None:
        if self._layer1 is None:
            return
        try:
            from explainability.shap_explainer import SHAPExplainer

            if self._shap is None:
                self._shap = SHAPExplainer(self._layer1._model)

            feat_cols = [c for c in sample_df.columns
                         if c not in {BINARY_LABEL_COL, MULTICLASS_LABEL_COL,
                                      "label_raw", "pred_binary", "confidence",
                                      "anomaly_score", "anomaly_detected",
                                      "attack_class"}]
            X_exp = sample_df[feat_cols].select_dtypes(
                include=[np.number]).replace([np.inf, -np.inf], np.nan).fillna(0)

            shap_res = self._shap.explain(X_exp, n_samples=min(50, len(X_exp)))
            if shap_res:
                self._n_explained += 1
                importance = self._shap.global_importance(shap_res)
                logger.info("SHAP top feature: %s (%.1f%%)",
                            importance[0][0], importance[0][1])
        except Exception as exc:
            logger.debug("SHAP narration error: %s", exc)

    # ------------------------------------------------------------------
    # Zero-day mining (periodic)
    # ------------------------------------------------------------------

    def _run_zd_mining(self, chunk: pd.DataFrame) -> None:
        try:
            num = chunk.select_dtypes(include=[np.number])
            if len(num) >= 50:
                patterns = self._zd_miner.mine(num)
                if patterns:
                    logger.info("Zero-day miner: %d new pattern(s) found",
                                len(patterns))
        except Exception as exc:
            logger.debug("Zero-day mining error: %s", exc)

    # ------------------------------------------------------------------
    # Session summary
    # ------------------------------------------------------------------

    def _estimate_fps(self, n_rows: int) -> float:
        """Estimate flows/sec based on session throughput so far."""
        elapsed = max(time.monotonic() - self._session_start, 0.001)
        return round((self._n_flows + n_rows) / elapsed, 0)

    def summary(self) -> None:
        elapsed = time.monotonic() - self._session_start
        fps     = self._n_flows / max(elapsed, 1)
        _banner = "=" * 60
        logger.info(_banner)
        logger.info("  SENTINEL IPS v2.0 — SESSION SUMMARY")
        logger.info(_banner)
        logger.info("  Total flows    : %d",      self._n_flows)
        logger.info("  Total attacks  : %d",      self._n_attacks)
        logger.info("  SHAP runs      : %d",      self._n_explained)
        logger.info("  Throughput avg : %.0f fps", fps)
        logger.info("  Runtime        : %.1fs",    elapsed)
        if self._events_buffer:
            logger.info("  Building attack timeline...")
            try:
                tl = self._timeline.build(
                    self._events_buffer[-10_000:],
                    campaign_id="session",
                )
                logger.info("  Timeline: %d phases, sophistication=%s",
                            len(tl.phase_transitions), tl.sophistication)
            except Exception:
                pass
        logger.info(_banner)

    def shutdown(self) -> None:
        """Flush all buffers and close file handles gracefully."""
        try:
            self._pkt_logger.close()
        except Exception:
            pass
        try:
            self._geo.close()
        except Exception:
            pass
        try:
            self._mistakes.save()
        except Exception:
            pass
        logger.info("SENTINEL IPS v2.0 shutdown complete")


# ---------------------------------------------------------------------------
# Simulate mode
# ---------------------------------------------------------------------------

def _run_simulate(args) -> None:
    """Replay CSV data through the full pipeline."""

    model_path = args.model or str(MODEL_DIR / "benchmarkids_binary.pkl")
    ips        = SentinelIPS(
        model_path=model_path,
        enforce_blocks=False,
    )

    data_glob = args.data or str(DATA_2017 / "**" / "*.csv")
    sample    = args.sample

    logger.info("Simulate mode: data=%s  sample=%.4f", data_glob, sample)
    logger.info("Loading dataset...")

    try:
        df = load_full_dataset(data_glob, sample_frac=sample)
    except FileNotFoundError as exc:
        logger.error("Dataset not found: %s", exc)
        logger.error("Run 'python train.py' first or place CSVs under datasets/")
        sys.exit(1)

    # Feature engineering
    eng = NetworkFeatureEngineer(keep_raw=True)
    df  = eng.transform(df)
    logger.info("Loaded %d flows for simulation", len(df))

    # Fit anomaly detector on benign sample
    benign_mask = df.get(BINARY_LABEL_COL, pd.Series(0, index=df.index)) == 0
    benign_df   = df[benign_mask].head(50_000)
    if len(benign_df) >= 100:
        feat_cols = [c for c in benign_df.select_dtypes(include=[np.number]).columns
                     if c not in {BINARY_LABEL_COL, MULTICLASS_LABEL_COL, "label_raw"}]
        ips._anomaly.fit(benign_df[feat_cols])
        ips._anomaly_fitted = True
        logger.info("Anomaly detector fitted on %d benign samples", len(benign_df))

    # Process in chunks
    n_chunks = 0
    for start in range(0, len(df), REALTIME_CHUNK_SIZE):
        chunk = df.iloc[start:start + REALTIME_CHUNK_SIZE].copy()
        ips.process_chunk(chunk)
        n_chunks += 1

    ips.summary()
    ips.shutdown()

    # Print dashboard URL
    logger.info("Launch dashboard: streamlit run dashboard/app.py")


# ---------------------------------------------------------------------------
# Live capture mode
# ---------------------------------------------------------------------------

def _run_live(args) -> None:
    """
    Real-time capture via Scapy.

    Raw packets are assembled into CIC-IDS-schema flow records by
    FlowCollector, engineered (bytes_per_pkt) by NetworkFeatureEngineer,
    then run through the existing SentinelIPS.process_chunk() pipeline —
    the same detection path simulate mode uses, just fed by live traffic
    instead of replayed CSV rows.

    Active countermeasures stay off unless --enforce-blocks is passed
    (default False): detections are still logged/alerted/blacklisted in
    threat_intel/ip_blacklist.txt, but no OS firewall rule is ever applied.
    """

    model_path = args.model or str(MODEL_DIR / "benchmarkids_binary.pkl")
    ips        = SentinelIPS(
        model_path=model_path,
        enforce_blocks=args.enforce_blocks,
    )

    interface  = args.interface or LIVE_INTERFACE_DEFAULT
    bpf_filter = args.bpf_filter or LIVE_BPF_FILTER
    logger.info("Live capture mode on interface: %s (filter=%r)", interface, bpf_filter)
    logger.warning(
        "Live capture requires elevated privileges (root/Npcap) "
        "and a fitted anomaly detector. Starting Scapy capture..."
    )

    collector = FlowCollector()
    eng       = NetworkFeatureEngineer(keep_raw=True)

    try:
        from scapy.sendrecv import AsyncSniffer
        flow_sniffer = AsyncSniffer(
            iface=interface, filter=bpf_filter,
            prn=collector.ingest_packet, store=False,
        )
        flow_sniffer.start()
        logger.info("Flow-assembling sniffer started on %s", interface)
    except Exception as exc:
        logger.error("Failed to start flow-assembling sniffer: %s", exc)
        ips.shutdown()
        return

    try:
        ips._pkt_logger.start_live_capture(interface, bpf_filter=bpf_filter)
        logger.info("Forensic packet logger capturing on %s", interface)
    except Exception as exc:
        logger.warning("Packet logger capture failed: %s", exc)

    logger.info("Live mode active — press Ctrl+C to stop")
    try:
        while True:
            time.sleep(FLOW_GC_INTERVAL_S)

            closed    = collector.pop_completed_flows()
            timed_out = collector.sweep_idle_flows()
            frames    = [f for f in (closed, timed_out) if not f.empty]
            if frames:
                flow_df = pd.concat(frames, ignore_index=True)
                flow_df = eng.transform(flow_df)
                ips.process_chunk(flow_df)
                del flow_df
                gc.collect()

            snap   = ips.monitor.snapshot()
            cstats = collector.get_stats()
            logger.info(
                "Live: attacks=%d  fps=%.0f  open_flows=%d  unique_ips=%d",
                snap["total_attacks"], snap["current_fps"],
                cstats["open_flows"], ips.attack_map.total_unique_ips(),
            )
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt — flushing remaining flows...")
        final_df = collector.flush_all()
        if not final_df.empty:
            ips.process_chunk(eng.transform(final_df))
            del final_df
            gc.collect()
        flow_sniffer.stop()
        ips.summary()
        ips.shutdown()


# ---------------------------------------------------------------------------
# Health check mode
# ---------------------------------------------------------------------------

def _run_health(args) -> None:
    """Import-only health check — verifies all 32 modules load cleanly."""
    _modules = [
        "config",
        "core.preprocessing", "core.features", "core.model", "core.flow_collector",
        "detection.layer1_ml", "detection.layer2_signatures", "detection.layer3_anomaly",
        "intelligence.threat_feeds", "intelligence.ip_reputation",
        "intelligence.domain_reputation", "intelligence.honeypot",
        "attribution.geolocator", "attribution.mitre_mapper", "attribution.threat_profiler",
        "response.ip_blacklister", "response.connection_terminator",
        "response.rate_limiter", "response.alert_dispatcher",
        "adaptive.mistake_collector", "adaptive.adaptive_trainer", "adaptive.zero_day_miner",
        "forensics.packet_logger", "forensics.timeline_builder", "forensics.compliance_reporter",
        "explainability.shap_explainer", "explainability.attack_narrator",
        "explainability.risk_scorer",
        "evaluation.metrics", "evaluation.reporter",
        "dashboard.live_monitor", "dashboard.attack_map",
    ]

    ok, fail = [], []
    for m in _modules:
        try:
            __import__(m)
            ok.append(m)
        except Exception as e:
            fail.append((m, str(e)))

    print(f"\nSENTINEL IPS v2.0 — Module Health Check")
    print("=" * 55)
    print(f"OK  : {len(ok)}/{len(_modules)}")
    for m, e in fail:
        print(f"FAIL: {m}")
        print(f"      {e}")
    if not fail:
        print("\nAll 32 modules operational.")
        print("Run: python train.py   to train models")
        print("Run: python sentinel.py simulate   to process data")
        print("Run: streamlit run dashboard/app.py   to open dashboard")
    sys.exit(0 if not fail else 1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SENTINEL IPS v2.0",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = p.add_subparsers(dest="mode", help="Operating mode")
    sub.required = True

    # --- simulate ---
    sim = sub.add_parser("simulate", help="Replay CSV data through full pipeline")
    sim.add_argument("--model",  default=None,
                     help="Path to trained BenchmarkIDS pkl")
    sim.add_argument("--data",   default=None,
                     help="Glob pattern for input CSVs")
    sim.add_argument("--sample", type=float, default=0.001,
                     help="Fraction of data to sample (0 < f <= 1.0)")

    # --- live ---
    live = sub.add_parser("live", help="Real-time packet capture")
    live.add_argument("--interface",     default=None,
                      help="Network interface for capture (default: config.LIVE_INTERFACE_DEFAULT)")
    live.add_argument("--bpf-filter",    default=None,
                      help="Berkeley Packet Filter expression (default: config.LIVE_BPF_FILTER)")
    live.add_argument("--model",         default=None,
                      help="Path to trained BenchmarkIDS pkl")
    live.add_argument("--enforce-blocks",action="store_true",
                      help="Enable OS-level IP blocking (requires root)")

    # --- health ---
    sub.add_parser("health", help="Verify all 32 modules load cleanly")

    return p


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    logger.info("SENTINEL IPS v2.0 starting in '%s' mode", args.mode)

    if args.mode == "simulate":
        _run_simulate(args)
    elif args.mode == "live":
        _run_live(args)
    elif args.mode == "health":
        _run_health(args)


if __name__ == "__main__":
    main()
