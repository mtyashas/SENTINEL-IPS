"""
detection/layer3_anomaly.py

Purpose: Zero-day and behavioural anomaly detection for SENTINEL IPS.
         Three complementary detectors:
           AnomalyDetector       — IsolationForest for unknown attack patterns
           BehavioralProfiler    — Per-device rolling baseline with 3-sigma alerts
           EncryptedTrafficAnalyzer — JA3-based analysis without TLS decryption

Inputs:  pd.DataFrame of flow features; per-device feature dicts.
Outputs: DataFrames annotated with anomaly_score / anomaly_detected;
         boolean anomaly flags; risk score dicts.

Usage:
    from detection.layer3_anomaly import (
        AnomalyDetector, BehavioralProfiler, EncryptedTrafficAnalyzer
    )
    detector = AnomalyDetector(contamination=0.01)
    detector.fit(X_train)
    results = detector.predict(X_live)
"""

import logging
import math
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known-malicious JA3 fingerprint prefixes (truncated for demonstration;
# replace with live threat-intel feed in production).
# ---------------------------------------------------------------------------
_KNOWN_MALICIOUS_JA3_PREFIXES: List[str] = [
    "e7d705",  # Cobalt Strike default
    "a0e9f5",  # Metasploit
    "6734f37",  # Emotet
    "51c64c",  # TrickBot
]

_WEAK_CIPHER_IDENTIFIERS: List[str] = [
    "RC4", "NULL", "EXPORT", "DES", "3DES", "MD5", "anon",
]

# Beaconing is flagged when connection frequency exceeds this threshold
# (connections per minute) and packet-size variance is extremely low —
# indicating automated, periodic C2 check-ins.
_BEACON_FREQ_THRESHOLD   = 20    # connections/min
_BEACON_VARIANCE_CEILING = 0.05  # near-constant packet sizes


class AnomalyDetector:
    """
    IsolationForest-based zero-day detector.

    Trains on a representative sample of benign traffic to build a normality
    boundary. Any flow whose isolation score falls below the contamination
    boundary is flagged as a potential zero-day or unknown attack.

    Parameters:
        contamination — expected proportion of anomalies in training data
                        (default: 0.01 → 1 %)

    Usage:
        detector = AnomalyDetector(contamination=0.01)
        detector.fit(X_benign)
        results = detector.predict(X_live)   # DataFrame with anomaly columns
        detector.save("models/anomaly_detector.pkl")
    """

    def __init__(self, contamination: float = 0.01) -> None:
        self.contamination = contamination
        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self._feature_cols: List[str] = []
        self._fitted: bool = False

    # ------------------------------------------------------------------
    # Fit
    # ------------------------------------------------------------------

    def fit(self, X: pd.DataFrame) -> "AnomalyDetector":
        """
        Train the IsolationForest on a baseline DataFrame.

        Inputs:  X — pd.DataFrame of numeric features (benign traffic preferred)
        Outputs: self (fluent interface)
        """
        if X.empty:
            raise ValueError("Cannot fit AnomalyDetector on empty DataFrame")

        self._feature_cols = list(X.columns)

        X_num = X.copy().replace([np.inf, -np.inf], np.nan).fillna(0.0)

        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X_num.values.astype(np.float64))

        self._model = IsolationForest(
            contamination=self.contamination,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)
        self._fitted = True
        logger.info(
            "AnomalyDetector fitted on %d samples, %d features, contamination=%.3f",
            len(X), len(self._feature_cols), self.contamination,
        )
        return self

    # ------------------------------------------------------------------
    # Predict
    # ------------------------------------------------------------------

    def predict(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Score flows against the fitted baseline.

        Inputs:  X — pd.DataFrame with same schema as training data
        Outputs: X with two new columns:
                   anomaly_score    — raw IsolationForest decision score
                                      (more negative = more anomalous)
                   anomaly_detected — boolean True if flagged as anomaly

        Missing columns are filled with 0.0. Extra columns are ignored.
        """
        if not self._fitted:
            raise RuntimeError("AnomalyDetector.fit() must be called before predict()")

        result = X.copy()

        # Align columns to training schema
        X_aligned = pd.DataFrame(index=X.index)
        for col in self._feature_cols:
            if col in X.columns:
                X_aligned[col] = pd.to_numeric(X[col], errors="coerce")
            else:
                X_aligned[col] = 0.0
        X_aligned = X_aligned.replace([np.inf, -np.inf], np.nan).fillna(0.0)

        try:
            X_scaled = self._scaler.transform(X_aligned.values.astype(np.float64))
            scores   = self._model.decision_function(X_scaled)
            labels   = self._model.predict(X_scaled)          # -1 = anomaly, 1 = normal
            result["anomaly_score"]    = scores
            result["anomaly_detected"] = (labels == -1)
        except Exception as exc:
            logger.error("AnomalyDetector.predict failed: %s", exc)
            result["anomaly_score"]    = 0.0
            result["anomaly_detected"] = False

        n_flagged = int(result["anomaly_detected"].sum())
        logger.debug("AnomalyDetector: %d / %d flows flagged", n_flagged, len(result))
        return result

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str) -> None:
        """Serialise model and scaler to a joblib file."""
        if not self._fitted:
            raise RuntimeError("Cannot save unfitted AnomalyDetector")
        payload = {
            "model":        self._model,
            "scaler":       self._scaler,
            "feature_cols": self._feature_cols,
            "contamination": self.contamination,
        }
        try:
            joblib.dump(payload, path)
            logger.info("AnomalyDetector saved to %s", Path(path).name)
        except Exception as exc:
            logger.error("Failed to save AnomalyDetector: %s", exc)
            raise

    @classmethod
    def load(cls, path: str) -> "AnomalyDetector":
        """Deserialise a previously saved AnomalyDetector."""
        try:
            payload = joblib.load(path)
        except Exception as exc:
            logger.error("Failed to load AnomalyDetector from %s: %s", path, exc)
            raise

        obj = cls(contamination=payload.get("contamination", 0.01))
        obj._model        = payload["model"]
        obj._scaler       = payload["scaler"]
        obj._feature_cols = payload["feature_cols"]
        obj._fitted       = True
        logger.info("AnomalyDetector loaded from %s (%d features)", Path(path).name, len(obj._feature_cols))
        return obj


# ---------------------------------------------------------------------------

class _DeviceProfile:
    """Rolling statistics for one device's traffic features."""

    __slots__ = ("_counts", "_means", "_m2s", "_threshold_sigma")

    def __init__(self, threshold_sigma: float = 3.0) -> None:
        self._counts:           Dict[str, int]   = defaultdict(int)
        self._means:            Dict[str, float] = defaultdict(float)
        self._m2s:              Dict[str, float] = defaultdict(float)   # Welford M2
        self._threshold_sigma:  float            = threshold_sigma

    def update(self, features: Dict[str, float]) -> None:
        """Welford online update for each numeric feature."""
        for key, raw_val in features.items():
            try:
                val = float(raw_val)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(val):
                continue
            n = self._counts[key] + 1
            delta  = val - self._means[key]
            self._means[key] += delta / n
            delta2 = val - self._means[key]
            self._m2s[key]   += delta * delta2
            self._counts[key] = n

    def std(self, key: str) -> float:
        n = self._counts.get(key, 0)
        if n < 2:
            return 0.0
        return math.sqrt(self._m2s[key] / (n - 1))

    def is_anomalous(self, features: Dict[str, float]) -> bool:
        """Return True if any feature exceeds baseline + threshold_sigma * std."""
        for key, raw_val in features.items():
            try:
                val = float(raw_val)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(val):
                continue
            if self._counts.get(key, 0) < 3:
                # Need at least 3 observations to establish a baseline
                continue
            std = self.std(key)
            if std == 0.0:
                # Zero variance — flag any non-zero deviation
                if abs(val - self._means[key]) > 0.0:
                    return True
                continue
            z = (val - self._means[key]) / std
            if abs(z) > self._threshold_sigma:
                return True
        return False

    def anomaly_score(self, features: Dict[str, float]) -> float:
        """Return the maximum z-score across all features (0 if baseline insufficient)."""
        max_z = 0.0
        for key, raw_val in features.items():
            try:
                val = float(raw_val)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(val):
                continue
            if self._counts.get(key, 0) < 3:
                continue
            std = self.std(key)
            if std == 0.0:
                z = abs(val - self._means[key]) * 1e6 if val != self._means[key] else 0.0
            else:
                z = abs((val - self._means[key]) / std)
            if z > max_z:
                max_z = z
        return max_z

    def to_dict(self) -> Dict:
        return {
            "observation_counts": dict(self._counts),
            "means":              dict(self._means),
            "stds":               {k: self.std(k) for k in self._counts},
            "threshold_sigma":    self._threshold_sigma,
        }


class BehavioralProfiler:
    """
    Per-device rolling-baseline anomaly detector.

    Maintains a Welford online-statistics profile for every observed device.
    After at least 3 observations, traffic exceeding baseline + 3σ on any
    feature is flagged as anomalous — detecting DDoS ramp-ups, port scans,
    data exfiltration spikes, and insider-threat deviations.

    Parameters: none (sigma threshold hard-coded to 3.0 per spec)

    Usage:
        profiler = BehavioralProfiler()
        for obs in baseline_observations:
            profiler.update_profile("device_001", obs)
        if profiler.is_anomalous("device_001", live_features):
            alert()
    """

    def __init__(self) -> None:
        self._profiles: Dict[str, _DeviceProfile] = {}
        logger.info("BehavioralProfiler initialised")

    def _get_or_create(self, device_id: str) -> _DeviceProfile:
        if device_id not in self._profiles:
            self._profiles[device_id] = _DeviceProfile(threshold_sigma=3.0)
        return self._profiles[device_id]

    def update_profile(self, device_id: str, features: Dict[str, float]) -> None:
        """
        Add a new observation to the device's rolling baseline.

        Inputs:
            device_id — unique device/IP/hostname identifier
            features  — dict of numeric feature names to values
        """
        try:
            self._get_or_create(device_id).update(features)
        except Exception as exc:
            logger.error("Profile update failed for %s: %s", device_id, exc)

    def is_anomalous(self, device_id: str, features: Dict[str, float]) -> bool:
        """
        Return True if current features deviate beyond 3σ from the device baseline.

        Returns False if the device has fewer than 3 observations (no baseline yet).

        Inputs:
            device_id — device identifier (must have prior update_profile calls)
            features  — current observation dict
        Outputs: bool
        """
        if device_id not in self._profiles:
            return False
        try:
            return self._profiles[device_id].is_anomalous(features)
        except Exception as exc:
            logger.error("is_anomalous failed for %s: %s", device_id, exc)
            return False

    def get_anomaly_score(self, device_id: str, features: Dict[str, float]) -> float:
        """
        Return the maximum z-score of current features against the device baseline.

        Returns 0.0 if no baseline exists yet.

        Inputs:
            device_id — device identifier
            features  — current observation dict
        Outputs: float (z-score; values > 3.0 indicate anomaly)
        """
        if device_id not in self._profiles:
            return 0.0
        try:
            return self._profiles[device_id].anomaly_score(features)
        except Exception as exc:
            logger.error("get_anomaly_score failed for %s: %s", device_id, exc)
            return 0.0

    def get_all_profiles(self) -> Dict[str, Dict]:
        """
        Return a serialisable snapshot of all device profiles.

        Outputs: dict mapping device_id → profile statistics dict
        """
        return {did: profile.to_dict() for did, profile in self._profiles.items()}


# ---------------------------------------------------------------------------

class EncryptedTrafficAnalyzer:
    """
    Encrypted traffic analysis without TLS decryption.

    Derives risk signals from behavioural metadata: connection frequency,
    packet-size variance, JA3 fingerprint reputation, and cipher-suite
    strength. Identifies beaconing (C2 check-ins) and malware-family
    fingerprints without inspecting payload content.

    Parameters: none

    Usage:
        analyzer = EncryptedTrafficAnalyzer()
        result = analyzer.analyze({
            "connection_frequency": 45,
            "packet_size_variance": 0.002,
            "ja3_fingerprint": "e7d705...",
            "cipher_suite": "TLS_RSA_WITH_RC4_128_MD5",
        })
    """

    def __init__(self) -> None:
        logger.info("EncryptedTrafficAnalyzer initialised")

    def analyze(self, flow_features: Dict) -> Dict:
        """
        Analyse a TLS flow's metadata for malicious indicators.

        Inputs:
            flow_features — dict with any subset of:
                connection_frequency   — connections per minute (float)
                packet_size_variance   — variance of packet sizes (float)
                ja3_fingerprint        — JA3 hash string
                ja3s_fingerprint       — JA3S hash string
                cipher_suite           — cipher suite name/ID string
                certificate_validity_days — days remaining on cert (int)
                tls_handshake_duration — handshake latency in ms (float)
                byte_distribution_entropy — Shannon entropy of byte dist (float)

        Outputs:
            dict with keys:
                ja3_risk_score        — 0.0–1.0 (1.0 = known malicious JA3)
                beaconing_detected    — bool
                suspicious_cipher     — bool
                anomaly_indicators    — list of human-readable flag strings
        """
        indicators: List[str] = []

        # --- JA3 fingerprint reputation ---
        ja3_risk = 0.0
        ja3 = str(flow_features.get("ja3_fingerprint", "")).lower().strip()
        if ja3:
            for prefix in _KNOWN_MALICIOUS_JA3_PREFIXES:
                if ja3.startswith(prefix.lower()):
                    ja3_risk = 1.0
                    indicators.append(f"known_malicious_ja3:{ja3[:12]}")
                    break
            if ja3_risk == 0.0 and len(ja3) == 32:
                # Valid MD5-length JA3 but unknown — mild suspicion
                ja3_risk = 0.1

        # --- Cipher suite strength ---
        cipher = str(flow_features.get("cipher_suite", "")).upper()
        suspicious_cipher = any(w in cipher for w in _WEAK_CIPHER_IDENTIFIERS)
        if suspicious_cipher:
            indicators.append(f"weak_cipher_suite:{cipher[:40]}")

        # --- Beaconing detection ---
        freq     = float(flow_features.get("connection_frequency", 0))
        variance = float(flow_features.get("packet_size_variance", 1.0))
        beaconing = (freq >= _BEACON_FREQ_THRESHOLD) and (variance <= _BEACON_VARIANCE_CEILING)
        if beaconing:
            indicators.append(
                f"beaconing:freq={freq:.1f}/min,variance={variance:.4f}"
            )

        # --- Certificate validity ---
        cert_days = flow_features.get("certificate_validity_days")
        if cert_days is not None:
            try:
                cert_days = int(cert_days)
                if cert_days < 0:
                    indicators.append("expired_certificate")
                elif cert_days < 7:
                    indicators.append(f"certificate_expiring_soon:{cert_days}d")
                elif cert_days > 3650:
                    indicators.append("unusually_long_certificate_validity")
            except (TypeError, ValueError):
                pass

        # --- Byte distribution entropy ---
        entropy = flow_features.get("byte_distribution_entropy")
        if entropy is not None:
            try:
                entropy = float(entropy)
                if entropy > 7.5:
                    indicators.append(f"high_entropy_payload:{entropy:.2f}")
                elif entropy < 0.5 and entropy >= 0:
                    indicators.append(f"low_entropy_payload:{entropy:.2f}")
            except (TypeError, ValueError):
                pass

        # --- Aggregate risk score ---
        risk_score = min(1.0, ja3_risk + (0.3 if suspicious_cipher else 0.0) + (0.4 if beaconing else 0.0))

        result = {
            "ja3_risk_score":     round(ja3_risk, 4),
            "beaconing_detected": beaconing,
            "suspicious_cipher":  suspicious_cipher,
            "anomaly_indicators": indicators,
            "aggregate_risk":     round(risk_score, 4),
        }

        if indicators:
            logger.info("EncryptedTrafficAnalyzer: %d indicator(s) — %s", len(indicators), indicators)

        return result
