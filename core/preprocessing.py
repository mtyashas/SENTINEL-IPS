"""
core/preprocessing.py

Purpose: Memory-safe CSV ingestion, schema alignment, cleaning, and label
         encoding for CIC-IDS-2017 and CIC-IDS-2018 network flow datasets.
Inputs:  Glob pattern pointing to raw CSV files, optional sample fraction.
Outputs: Cleaned pandas DataFrame with standardised column names, binary
         ``label`` column (0 = benign, 1 = attack), and integer
         ``label_class`` column (index into ATTACK_CLASSES).

Usage:
    from core.preprocessing import load_full_dataset
    from config import DATA_2017
    df = load_full_dataset(str(DATA_2017 / '**' / '*.csv'), sample_frac=0.05)
"""

import gc
import glob as _glob
import logging
import os
from pathlib import Path
from typing import Generator, List, Optional

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

from config import (
    ATTACK_CLASSES,
    ATTACK_LABEL_MAP,
    BINARY_LABEL_COL,
    CHUNK_SIZE,
    COL_REMAP_2018,
    MULTICLASS_LABEL_COL,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CIC-IDS-2017 column rename map
# (columns after stripping whitespace → standardised snake_case names)
# ---------------------------------------------------------------------------

_COL_REMAP_2017: dict[str, str] = {
    "Destination Port":             "destination_port",
    "Flow Duration":                "flow_duration",
    "Total Fwd Packets":            "total_fwd_packets",
    "Total Backward Packets":       "total_backward_packets",
    "Total Length of Fwd Packets":  "total_length_of_fwd_packets",
    "Total Length of Bwd Packets":  "total_length_of_bwd_packets",
    "Fwd Packet Length Max":        "fwd_packet_length_max",
    "Fwd Packet Length Min":        "fwd_packet_length_min",
    "Fwd Packet Length Mean":       "fwd_packet_length_mean",
    "Fwd Packet Length Std":        "fwd_packet_length_std",
    "Bwd Packet Length Max":        "bwd_packet_length_max",
    "Bwd Packet Length Min":        "bwd_packet_length_min",
    "Bwd Packet Length Mean":       "bwd_packet_length_mean",
    "Bwd Packet Length Std":        "bwd_packet_length_std",
    "Flow Bytes/s":                 "flow_bytes_per_s",
    "Flow Packets/s":               "flow_packets_per_s",
    "Flow IAT Mean":                "flow_iat_mean",
    "Flow IAT Std":                 "flow_iat_std",
    "Flow IAT Max":                 "flow_iat_max",
    "Flow IAT Min":                 "flow_iat_min",
    "Fwd IAT Total":                "fwd_iat_total",
    "Fwd IAT Mean":                 "fwd_iat_mean",
    "Fwd IAT Std":                  "fwd_iat_std",
    "Fwd IAT Max":                  "fwd_iat_max",
    "Fwd IAT Min":                  "fwd_iat_min",
    "Bwd IAT Total":                "bwd_iat_total",
    "Bwd IAT Mean":                 "bwd_iat_mean",
    "Bwd IAT Std":                  "bwd_iat_std",
    "Bwd IAT Max":                  "bwd_iat_max",
    "Bwd IAT Min":                  "bwd_iat_min",
    "Fwd PSH Flags":                "fwd_psh_flags",
    "Bwd PSH Flags":                "bwd_psh_flags",
    "Fwd URG Flags":                "fwd_urg_flags",
    "Bwd URG Flags":                "bwd_urg_flags",
    "Fwd Header Length":            "fwd_header_length",
    "Bwd Header Length":            "bwd_header_length",
    "Fwd Packets/s":                "fwd_packets_per_s",
    "Bwd Packets/s":                "bwd_packets_per_s",
    "Min Packet Length":            "min_packet_length",
    "Max Packet Length":            "max_packet_length",
    "Packet Length Mean":           "packet_length_mean",
    "Packet Length Std":            "packet_length_std",
    "Packet Length Variance":       "packet_length_variance",
    "FIN Flag Count":               "fin_flag_count",
    "SYN Flag Count":               "syn_flag_count",
    "RST Flag Count":               "rst_flag_count",
    "PSH Flag Count":               "psh_flag_count",
    "ACK Flag Count":               "ack_flag_count",
    "URG Flag Count":               "urg_flag_count",
    "CWE Flag Count":               "cwe_flag_count",
    "ECE Flag Count":               "ece_flag_count",
    "Down/Up Ratio":                "down_per_up_ratio",
    "Average Packet Size":          "average_packet_size",
    "Avg Fwd Segment Size":         "avg_fwd_segment_size",
    "Avg Bwd Segment Size":         "avg_bwd_segment_size",
    "Fwd Avg Bytes/Bulk":           "fwd_avg_bytes_per_bulk",
    "Fwd Avg Packets/Bulk":         "fwd_avg_packets_per_bulk",
    "Fwd Avg Bulk Rate":            "fwd_avg_bulk_rate",
    "Bwd Avg Bytes/Bulk":           "bwd_avg_bytes_per_bulk",
    "Bwd Avg Packets/Bulk":         "bwd_avg_packets_per_bulk",
    "Bwd Avg Bulk Rate":            "bwd_avg_bulk_rate",
    "Subflow Fwd Packets":          "subflow_fwd_packets",
    "Subflow Fwd Bytes":            "subflow_fwd_bytes",
    "Subflow Bwd Packets":          "subflow_bwd_packets",
    "Subflow Bwd Bytes":            "subflow_bwd_bytes",
    "Init_Win_bytes_forward":       "init_win_bytes_forward",
    "Init_Win_bytes_backward":      "init_win_bytes_backward",
    "act_data_pkt_fwd":             "act_data_pkt_fwd",
    "min_seg_size_forward":         "min_seg_size_forward",
    "Active Mean":                  "active_mean",
    "Active Std":                   "active_std",
    "Active Max":                   "active_max",
    "Active Min":                   "active_min",
    "Idle Mean":                    "idle_mean",
    "Idle Std":                     "idle_std",
    "Idle Max":                     "idle_max",
    "Idle Min":                     "idle_min",
}

# ---------------------------------------------------------------------------
# Multi-class label maps  (raw string → ATTACK_CLASSES member name)
# ---------------------------------------------------------------------------

_LABEL_2017_TO_CLASS: dict[str, str] = {
    "BENIGN":                          "BENIGN",
    "FTP-Patator":                     "BruteForce",
    "SSH-Patator":                     "BruteForce",
    "DoS slowloris":                   "DoS",
    "DoS Slowhttptest":                "DoS",
    "DoS Hulk":                        "DoS",
    "DoS GoldenEye":                   "DoS",
    "Heartbleed":                      "Heartbleed",
    "Web Attack – Brute Force":   "WebAttack",
    "Web Attack – XSS":           "WebAttack",
    "Web Attack – Sql Injection":  "WebAttack",
    "Web Attack – Brute Force":        "WebAttack",
    "Web Attack – XSS":                "WebAttack",
    "Web Attack – Sql Injection":      "WebAttack",
    "Infiltration":                    "Infiltration",
    "Bot":                             "Bot",
    "DDoS":                            "DDoS",
    "PortScan":                        "PortScan",
}

_LABEL_2018_TO_CLASS: dict[str, str] = {
    "Benign":                   "BENIGN",
    "BENIGN":                   "BENIGN",
    "FTP-BruteForce":           "BruteForce",
    "SSH-Bruteforce":           "BruteForce",
    "DoS attacks-Hulk":         "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    "DoS attacks-GoldenEye":    "DoS",
    "DoS attacks-Slowloris":    "DoS",
    "DDoS attacks-LOIC-HTTP":   "DDoS",
    "DDOS attack-HOIC":         "DDoS",
    "DDOS attack-LOIC-UDP":     "DDoS",
    "Brute Force -Web":         "WebAttack",
    "Brute Force -XSS":         "WebAttack",
    "SQL Injection":            "WebAttack",
    "Infilteration":            "Infiltration",
    "Bot":                      "Bot",
}

# Pre-computed class name → integer index lookup
_CLASS_TO_INT: dict[str, int] = {cls: i for i, cls in enumerate(ATTACK_CLASSES)}


# ---------------------------------------------------------------------------
# SchemaAligner
# ---------------------------------------------------------------------------

class SchemaAligner(BaseEstimator, TransformerMixin):
    """
    Aligns a raw CIC-IDS-2017 or CIC-IDS-2018 DataFrame to a unified schema.

    Detects dataset year from column names, applies the appropriate rename
    dictionary, strips whitespace from all column names, and normalises the
    label column to a canonical ``label_raw`` column for downstream encoding.

    Inputs:  Raw DataFrame chunk with original dataset column names.
    Outputs: DataFrame with standardised snake_case column names and a
             ``label_raw`` column containing the original label string.

    Usage:
        aligner = SchemaAligner()
        aligned = aligner.fit_transform(raw_chunk)
    """

    def __init__(self) -> None:
        self.year_: Optional[int] = None
        self._remap: Optional[dict] = None

    def fit(self, X: pd.DataFrame, y=None) -> "SchemaAligner":
        stripped = {c.strip() for c in X.columns}
        if "Dst Port" in stripped:
            self.year_ = 2018
            self._remap = COL_REMAP_2018
        else:
            self.year_ = 2017
            self._remap = _COL_REMAP_2017
        return self

    def transform(self, X: pd.DataFrame, y=None) -> pd.DataFrame:
        if self._remap is None:
            self.fit(X)

        X = X.copy()
        # Strip whitespace from all column names first
        X.columns = [c.strip() for c in X.columns]

        # Apply rename (only for columns that exist)
        rename_map = {k: v for k, v in self._remap.items() if k in X.columns}
        X = X.rename(columns=rename_map)

        # Canonicalise label column → label_raw
        for candidate in ("Label", "label", "LABEL"):
            if candidate in X.columns:
                X = X.rename(columns={candidate: "label_raw"})
                break

        return X


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _clean_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    """Remove stray header rows, replace Inf with NaN, clip extremes, dedup."""
    # Drop literal header rows injected by 2018 CIC tool
    if "label_raw" in chunk.columns:
        chunk = chunk[chunk["label_raw"] != "Label"]

    # Replace Inf/-Inf with NaN, then clip remaining numeric extremes
    chunk = chunk.replace([np.inf, -np.inf], np.nan)
    numeric_cols = chunk.select_dtypes(include=[np.number]).columns
    if len(numeric_cols):
        chunk[numeric_cols] = chunk[numeric_cols].clip(-1e15, 1e15)

    # Drop rows where every numeric column is NaN (completely empty flows)
    chunk = chunk.dropna(subset=numeric_cols, how="all")

    # Remove exact duplicates
    chunk = chunk.drop_duplicates()

    return chunk.reset_index(drop=True)


def _encode_labels(chunk: pd.DataFrame, year: int) -> pd.DataFrame:
    """
    Add binary ``label`` (0/1) and integer ``label_class`` columns.

    For 2017 data  : derives labels from known CIC-IDS-2017 label strings.
    For 2018 data  : uses ATTACK_LABEL_MAP from config; drops stray header rows
                     (label == -1 sentinel from ATTACK_LABEL_MAP).
    """
    if "label_raw" not in chunk.columns:
        logger.warning("label_raw column missing — label encoding skipped")
        chunk[BINARY_LABEL_COL] = -1
        chunk[MULTICLASS_LABEL_COL] = 0
        return chunk

    raw = chunk["label_raw"].astype(str).str.strip()

    if year == 2017:
        chunk[BINARY_LABEL_COL] = (raw != "BENIGN").astype(np.int8)
        mc_class = raw.map(_LABEL_2017_TO_CLASS).fillna("BENIGN")
        chunk[MULTICLASS_LABEL_COL] = mc_class.map(_CLASS_TO_INT).fillna(0).astype(np.int8)
    else:
        binary = raw.map(ATTACK_LABEL_MAP)
        # Discard stray header rows (sentinel -1)
        valid = binary.notna() & (binary != -1)
        chunk = chunk[valid].copy()
        raw = raw[valid]
        chunk[BINARY_LABEL_COL] = binary[valid].fillna(1).astype(np.int8)
        mc_class = raw.map(_LABEL_2018_TO_CLASS).fillna("BENIGN")
        chunk[MULTICLASS_LABEL_COL] = mc_class.map(_CLASS_TO_INT).fillna(0).astype(np.int8)

    chunk = chunk.drop(columns=["label_raw"], errors="ignore")
    return chunk.reset_index(drop=True)


def _find_csv_files(glob_pattern: str) -> List[Path]:
    """Return sorted list of real CSV files matching glob_pattern (directories excluded)."""
    try:
        matches = _glob.glob(glob_pattern, recursive=True)
        files = sorted(
            Path(p) for p in matches
            if os.path.isfile(p) and p.lower().endswith(".csv")
        )
        logger.info("Found %d CSV file(s) for pattern: %s", len(files), glob_pattern)
        return files
    except Exception as exc:
        logger.error("File scan failed for pattern %s: %s", glob_pattern, exc)
        return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def stream_csv_chunks(
    file_path: "Path | str",
    chunk_size: int = CHUNK_SIZE,
    sample_frac: float = 1.0,
) -> Generator[pd.DataFrame, None, None]:
    """
    Generator yielding cleaned, schema-aligned chunks from a single CSV file.

    Inputs:
        file_path   — path to CSV file (str or Path)
        chunk_size  — rows per chunk (default CHUNK_SIZE from config)
        sample_frac — fraction of each chunk to keep (0 < frac <= 1.0)
    Outputs:
        Generator of cleaned pd.DataFrame chunks with unified column names,
        ``label`` (binary) and ``label_class`` (integer) columns.

    Usage:
        for chunk in stream_csv_chunks(path, sample_frac=0.1):
            train_on(chunk)
    """
    file_path = Path(file_path)
    aligner = SchemaAligner()
    aligner_fitted = False
    year: Optional[int] = None

    try:
        reader = pd.read_csv(
            file_path,
            chunksize=chunk_size,
            low_memory=False,
            on_bad_lines="skip",
        )
        for chunk in reader:
            if chunk.empty:
                continue

            try:
                if not aligner_fitted:
                    aligner.fit(chunk)
                    year = aligner.year_
                    aligner_fitted = True
                    logger.debug(
                        "Detected dataset year %d from %s", year, file_path.name
                    )

                chunk = aligner.transform(chunk)
                chunk = _clean_chunk(chunk)
                chunk = _encode_labels(chunk, year)  # type: ignore[arg-type]

                if sample_frac < 1.0 and len(chunk) > 0:
                    n = max(1, int(len(chunk) * sample_frac))
                    chunk = chunk.sample(n=n, random_state=42)

                if not chunk.empty:
                    yield chunk

            except Exception as exc:
                logger.error(
                    "Chunk processing error in %s: %s", file_path.name, exc
                )
                continue
            finally:
                gc.collect()

    except PermissionError:
        logger.warning("Permission denied — skipping: %s", file_path)
    except OSError as exc:
        logger.error("OS error reading %s: %s", file_path, exc)
    except Exception as exc:
        logger.error("Unexpected error reading %s: %s", file_path, exc)


def load_full_dataset(
    glob_pattern: str,
    sample_frac: float = 1.0,
) -> pd.DataFrame:
    """
    Load and combine all CSV files matching glob_pattern into a single DataFrame.

    Applies memory-safe chunked reading (max CHUNK_SIZE rows per chunk),
    schema alignment, NaN/Inf cleaning, duplicate removal, and label encoding.
    Returns a DataFrame sampled to approximately sample_frac of total rows.

    Inputs:
        glob_pattern — e.g. str(DATA_2017 / '**' / '*.csv')
        sample_frac  — fraction to sample per chunk (0 < frac <= 1.0)
    Outputs:
        Cleaned pd.DataFrame with unified schema, ``label`` and
        ``label_class`` columns present.

    Usage:
        df = load_full_dataset(str(DATA_2017 / '**' / '*.csv'), sample_frac=0.05)
    """
    files = _find_csv_files(glob_pattern)
    if not files:
        raise FileNotFoundError(
            f"No CSV files found matching pattern: {glob_pattern}"
        )

    frames: List[pd.DataFrame] = []
    total_rows = 0

    for fpath in files:
        file_rows = 0
        for chunk in stream_csv_chunks(fpath, sample_frac=sample_frac):
            frames.append(chunk)
            total_rows += len(chunk)
            file_rows += len(chunk)
        logger.info("  %s → %d rows (sampled)", fpath.name, file_rows)

    if not frames:
        raise RuntimeError(
            "No data could be loaded — all files were empty or unreadable"
        )

    logger.info("Concatenating %d chunks, %d rows total", len(frames), total_rows)
    df = pd.concat(frames, ignore_index=True)

    # Final global dedup across files
    df = df.drop_duplicates().reset_index(drop=True)

    del frames
    gc.collect()

    logger.info("Final dataset shape: %s", df.shape)
    return df
