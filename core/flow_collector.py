"""
core/flow_collector.py

Purpose: Assemble live-captured Scapy packets into CIC-IDS-style bidirectional
         network flow records — the raw-packet-to-flow-feature bridge needed
         to feed live traffic into detection.layer1_ml.MLDetectionLayer,
         which was trained exclusively on pre-computed CICFlowMeter flow
         features (see models/benchmarkids_feature_cols.pkl for the exact
         79-column schema).
Inputs:  Scapy packet objects, fed one at a time via ingest_packet() —
         typically called from an AsyncSniffer capture-thread callback.
Outputs: pd.DataFrame rows with the 78 raw CIC-IDS flow-feature columns
         (all of models/benchmarkids_feature_cols.pkl except bytes_per_pkt)
         plus identity columns (src_ip, dst_ip, src_port, protocol,
         destination_port) used downstream for event building.

Known approximations (documented per CLAUDE.md's Known Issues convention,
not silently shipped): bulk-transfer stats, subflow stats, and active/idle
period stats are best-effort reimplementations of CICFlowMeter heuristics
that are known to be hard to reproduce bit-exact even by other CICFlowMeter
reimplementations. None of these are in the top-15 SHAP feature ranking,
so this is a low-risk, explicitly documented simplification.

bytes_per_pkt (SHAP rank #6, 4.64% importance) is intentionally NOT computed
here — call core.features.NetworkFeatureEngineer.transform() on this
module's output before running inference, exactly as simulate mode already
does, rather than duplicating that arithmetic.

Usage:
    from core.flow_collector import FlowCollector
    collector = FlowCollector()

    from scapy.sendrecv import AsyncSniffer
    sniffer = AsyncSniffer(iface="eth0", prn=collector.ingest_packet, store=False)
    sniffer.start()

    completed_df = collector.pop_completed_flows()   # call periodically
    timed_out_df = collector.sweep_idle_flows()       # call periodically
    final_df     = collector.flush_all()              # call on shutdown
"""

import logging
import threading
import time
from collections import Counter, defaultdict, deque
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from config import (
    FLOW_ACTIVE_TIMEOUT_S,
    FLOW_IDLE_TIMEOUT_S,
    FLOW_MAX_OPEN,
)

try:
    # Importing here (rather than only inside _parse_packet) registers Ether/IP
    # into scapy's conf.l2types at module-load time. AsyncSniffer's capture
    # socket resolves its link-layer dissection class exactly once, when the
    # socket opens — if that table isn't populated yet, every packet for the
    # rest of the session silently falls back to undissected Raw, and
    # `IP not in pkt` below is then always True. Importing early (before any
    # sniffer is constructed) avoids that.
    from scapy.layers.inet import IP, TCP, UDP
except ImportError:
    IP = TCP = UDP = None  # type: ignore

logger = logging.getLogger(__name__)

# Standard TCP header flags byte bitmasks
_FIN = 0x01
_SYN = 0x02
_RST = 0x04
_PSH = 0x08
_ACK = 0x10
_URG = 0x20
_ECE = 0x40
_CWR = 0x80

# Bulk-transfer heuristic thresholds (best-effort approximation — see module docstring)
_BULK_MIN_PKTS  = 4     # consecutive same-direction packets to count as a "bulk"
_BULK_MAX_GAP_S = 1.0   # max inter-packet gap (s) within a bulk run

# Minimum idle time before a fresh SYN on an already-tracked 5-tuple is
# treated as a new connection reusing the port, rather than a retransmitted
# SYN for the same in-progress handshake (TCP's initial RTO is normally
# >=1s, so 3s comfortably avoids that ambiguity).
_SYN_REUSE_IDLE_S = 3.0

# Per-packet and per-flow payload capture caps for Layer 2 signature matching
# (detection/layer2_signatures.py) — bounded so a flow can never accumulate
# unbounded memory from payload bytes, matching the project's memory-safety
# standard. Only the first data-carrying packet's payload is kept per flow;
# injection/XSS/traversal patterns appear at the start of a request.
_PAYLOAD_CAP_BYTES = 2048

# Cross-flow beacon (Bot/C2) detection tuning. A single flow's own features
# carry no information about "same source hit the same destination on a
# regular interval, repeatedly" -- confirmed live 2026-07-30: a simulated
# C2 beacon (one GET every 10s) produced zero detections at any confidence,
# because one isolated request looks exactly like ordinary browsing. This
# tracks connection *start times* per (src_ip, dst_ip) pair across flows to
# give sentinel.py's _run_beacon() something to check.
#
# _BEACON_MAX_CV is a naive heuristic with a known ceiling: real C2 malware
# usually adds deliberate jitter specifically to defeat interval-regularity
# detection like this, and 0.25 was picked by eye against this lab's own
# simulated beacon (near-zero jitter, sleep 10s exactly) rather than
# real-world malware samples. This catches unsophisticated/naive beaconing,
# not evasive C2 -- upgrade path is a proper time-series/frequency-domain
# analysis if that's ever needed.
#
# _BEACON_MIN_MEAN_INTERVAL_S exists because regularity alone isn't enough:
# confirmed live 2026-08-01, nmap -sS -p1-1000 mislabelled PortScan as Bot,
# because a fast port scan's SYN probes land on the same destination IP at
# a very consistent, tight pace -- just as low-CV as a genuine beacon, only
# on a millisecond timescale instead of seconds-to-minutes. CV alone can't
# tell "patient beacon" from "fast, evenly-paced scan" since it never looks
# at the actual interval size. Real C2 checks in on the order of seconds to
# minutes; nothing faster should ever qualify regardless of how regular it
# looks.
_BEACON_HISTORY_LEN         = 20     # connections tracked per (src,dst) pair
_BEACON_MIN_CONNECTIONS     = 5      # minimum history before scoring at all
_BEACON_MAX_CV              = 0.25   # interval coefficient-of-variation ceiling
_BEACON_MIN_MEAN_INTERVAL_S = 2.0    # floor below which it's a scan, not a beacon

# Cross-flow DoS/DDoS flood detection tuning. Reads the same _conn_history
# beacon_score() uses, just interpreted as raw rate instead of regularity --
# confirmed live 2026-08-20/21: an hping3 SYN flood was reliably caught by
# the binary model but the multiclass model couldn't name it, falling back
# to the generic ATTACK label, because one flood packet looks like one
# failed connection attempt in isolation. _BEACON_MIN_MEAN_INTERVAL_S (2s)
# deliberately excludes anything this fast from beacon scoring (a fast,
# evenly-paced scan looks identical to a beacon by regularity alone) --
# this constant is the signal for that excluded fast range.
#
# _DOS_RATE_THRESHOLD_PER_S is a naive threshold, same class of limitation
# as _BEACON_MAX_CV: tuned against this lab's own hping3 capture, not
# validated against production-scale legitimate traffic (many real users
# behind one NAT gateway could plausibly open connections fast enough to
# cross a poorly-chosen threshold), and defeated by an attacker who
# deliberately throttles below it. See
# docs/superpowers/specs/2026-08-23-dos-ddos-multiclass-retrain-design.md
# for the disclosed limitation and the production-readiness follow-up
# (adaptive, baseline-relative thresholding) this doesn't attempt to solve.
_DOS_MIN_CONNECTIONS        = 2      # minimum history before scoring at all
_DOS_RATE_THRESHOLD_PER_S   = 10.0   # connections/sec at or above this = flood-shaped
_DOS_MIN_PORT_CONCENTRATION = 0.5    # share of conns on the single busiest
                                      # port required to call it a flood,
                                      # not a scan -- confirmed live
                                      # 2026-08-24: without this, a fast
                                      # nmap scan's PortScan label got
                                      # silently overridden to DoS, since a
                                      # scan's connection *rate* alone looks
                                      # identical to a flood's.

FlowKey = Tuple[str, int, str, int, int]   # (ip_a, port_a, ip_b, port_b, proto)


class _PacketInfo:
    """Fields extracted from one raw packet, needed for flow accounting."""

    __slots__ = (
        "ts", "src_ip", "dst_ip", "proto", "src_port", "dst_port",
        "length", "header_len", "payload_len", "tcp_flags", "tcp_window",
        "payload",
    )

    def __init__(
        self, ts: float, src_ip: str, dst_ip: str, proto: int,
        src_port: int, dst_port: int, length: int, header_len: int,
        payload_len: int, tcp_flags: int, tcp_window: int,
        payload: bytes = b"",
    ) -> None:
        self.ts          = ts
        self.src_ip       = src_ip
        self.dst_ip       = dst_ip
        self.proto        = proto
        self.src_port     = src_port
        self.dst_port     = dst_port
        self.length       = length
        self.header_len   = header_len
        self.payload_len  = payload_len
        self.tcp_flags    = tcp_flags
        self.tcp_window   = tcp_window
        self.payload      = payload


def _parse_packet(pkt) -> Optional[_PacketInfo]:
    """Extract flow-accounting fields from a raw Scapy packet. Returns None
    for non-IP traffic (ARP, etc.) — those carry no flow-feature signal."""
    if IP is None or IP not in pkt:
        return None
    ip = pkt[IP]

    length     = int(getattr(ip, "len", 0) or 0) or len(bytes(ip))
    header_len = int(getattr(ip, "ihl", 5) or 5) * 4
    src_port = dst_port = 0
    tcp_flags = tcp_window = 0

    payload_bytes = b""

    if TCP in pkt:
        tcp        = pkt[TCP]
        src_port   = int(tcp.sport)
        dst_port   = int(tcp.dport)
        tcp_flags  = int(tcp.flags)
        tcp_window = int(tcp.window)
        header_len += int(getattr(tcp, "dataofs", 5) or 5) * 4
        # Bounded at extraction time (not just truncated later) so a single
        # oversized packet can't inflate per-packet memory before capping —
        # Layer 2 signature matching only needs the first _PAYLOAD_CAP_BYTES
        # to catch injection/XSS/traversal patterns, which appear early in
        # a request (query string, form body prefix, headers).
        payload_bytes = bytes(tcp.payload)[:_PAYLOAD_CAP_BYTES]
    elif UDP in pkt:
        udp      = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        header_len += 8
        payload_bytes = bytes(udp.payload)[:_PAYLOAD_CAP_BYTES]

    payload_len = max(length - header_len, 0)
    ts = float(getattr(pkt, "time", time.time()))

    return _PacketInfo(
        ts=ts, src_ip=str(ip.src), dst_ip=str(ip.dst), proto=int(ip.proto),
        src_port=src_port, dst_port=dst_port, length=length,
        header_len=header_len, payload_len=payload_len,
        tcp_flags=tcp_flags, tcp_window=tcp_window,
        payload=payload_bytes,
    )


def _canonical_key(pi: _PacketInfo) -> FlowKey:
    """Normalize a packet's 5-tuple so both directions of a conversation
    map to the same flow-table entry, regardless of which side sent first."""
    a = (pi.src_ip, pi.src_port)
    b = (pi.dst_ip, pi.dst_port)
    if a <= b:
        return (a[0], a[1], b[0], b[1], pi.proto)
    return (b[0], b[1], a[0], a[1], pi.proto)


class _FlowState:
    """Mutable accumulator for one open bidirectional flow. The endpoint
    that sent the first packet is fixed as "forward" for the flow's
    lifetime, matching CICFlowMeter's direction semantics."""

    def __init__(self, pi: _PacketInfo) -> None:
        self.fwd_addr: Tuple[str, int] = (pi.src_ip, pi.src_port)
        self.src_ip   = pi.src_ip
        self.dst_ip   = pi.dst_ip
        self.src_port = pi.src_port
        self.dst_port = pi.dst_port
        self.proto    = pi.proto

        self.first_ts = pi.ts
        self.last_ts  = pi.ts

        self.fwd_lengths: List[float] = []
        self.bwd_lengths: List[float] = []
        self.fwd_ts: List[float] = []
        self.bwd_ts: List[float] = []
        self.all_ts: List[float] = []

        self.fwd_header_bytes = 0
        self.bwd_header_bytes = 0
        self.fwd_psh = 0
        self.bwd_psh = 0
        self.fwd_urg = 0
        self.bwd_urg = 0

        self.flag_counts = {"fin": 0, "syn": 0, "rst": 0, "psh": 0,
                             "ack": 0, "urg": 0, "cwe": 0, "ece": 0}

        self.init_win_fwd: Optional[int] = None
        self.init_win_bwd: Optional[int] = None
        self.act_data_pkt_fwd = 0
        self.min_seg_size_fwd: Optional[int] = None
        self.payload_sample: bytes = b""   # first data-carrying packet only

        # Bulk-transfer run tracking (best-effort — see module docstring)
        self._bulk_dir: Optional[str] = None
        self._bulk_run_pkts  = 0
        self._bulk_run_bytes = 0
        self._bulk_run_start = 0.0
        self._bulk_last_ts   = 0.0
        self.fwd_bulk_bytes: List[int] = []
        self.fwd_bulk_pkts:  List[int] = []
        self.fwd_bulk_durations: List[float] = []
        self.bwd_bulk_bytes: List[int] = []
        self.bwd_bulk_pkts:  List[int] = []
        self.bwd_bulk_durations: List[float] = []

        # Active/idle period tracking (gap > FLOW_ACTIVE_TIMEOUT_S starts a new segment)
        self._active_start = pi.ts
        self.active_periods: List[float] = []
        self.idle_periods: List[float] = []
        self.n_active_segments = 1

        self.closed_by: Optional[str] = None
        self._fin_seen = {"fwd": False, "bwd": False}
        self._fin_close_pending = False

        self.ingest(pi)

    def _direction(self, pi: _PacketInfo) -> str:
        return "fwd" if (pi.src_ip, pi.src_port) == self.fwd_addr else "bwd"

    def ingest(self, pi: _PacketInfo) -> None:
        direction = self._direction(pi)
        gap = pi.ts - self.last_ts if self.all_ts else 0.0

        if self.all_ts and gap > FLOW_ACTIVE_TIMEOUT_S:
            self.active_periods.append(self.last_ts - self._active_start)
            self.idle_periods.append(gap)
            self._active_start = pi.ts
            self.n_active_segments += 1

        self.last_ts = pi.ts
        self.all_ts.append(pi.ts)

        if not self.payload_sample and pi.payload:
            self.payload_sample = pi.payload

        if direction == "fwd":
            self.fwd_lengths.append(float(pi.length))
            self.fwd_ts.append(pi.ts)
            self.fwd_header_bytes += pi.header_len
            if pi.payload_len > 0:
                self.act_data_pkt_fwd += 1
            if pi.tcp_window and self.init_win_fwd is None:
                self.init_win_fwd = pi.tcp_window
            if self.min_seg_size_fwd is None or pi.header_len < self.min_seg_size_fwd:
                self.min_seg_size_fwd = pi.header_len
            if pi.tcp_flags & _PSH:
                self.fwd_psh += 1
            if pi.tcp_flags & _URG:
                self.fwd_urg += 1
        else:
            self.bwd_lengths.append(float(pi.length))
            self.bwd_ts.append(pi.ts)
            self.bwd_header_bytes += pi.header_len
            if pi.tcp_window and self.init_win_bwd is None:
                self.init_win_bwd = pi.tcp_window
            if pi.tcp_flags & _PSH:
                self.bwd_psh += 1
            if pi.tcp_flags & _URG:
                self.bwd_urg += 1

        if pi.tcp_flags & _FIN:
            self.flag_counts["fin"] += 1
            self._fin_seen[direction] = True
        if pi.tcp_flags & _SYN:
            self.flag_counts["syn"] += 1
        if pi.tcp_flags & _RST:
            self.flag_counts["rst"] += 1
        if pi.tcp_flags & _PSH:
            self.flag_counts["psh"] += 1
        if pi.tcp_flags & _ACK:
            self.flag_counts["ack"] += 1
        if pi.tcp_flags & _URG:
            self.flag_counts["urg"] += 1
        if pi.tcp_flags & _CWR:
            self.flag_counts["cwe"] += 1
        if pi.tcp_flags & _ECE:
            self.flag_counts["ece"] += 1

        self._update_bulk(direction, pi)

        if pi.tcp_flags & _RST:
            self.closed_by = "rst"
        elif self._fin_seen["fwd"] and self._fin_seen["bwd"]:
            # A standard TCP close is FIN -> ACK -> FIN -> ACK: the packet
            # that sets the second fin_seen flag is *not* the last packet of
            # the connection — the peer's ACK of that second FIN still
            # follows it. Closing immediately here would pop the flow before
            # that trailing ACK arrives, orphaning it into its own spurious
            # one-packet "flow". Wait one more ingest() call before finalizing.
            if self._fin_close_pending:
                self.closed_by = "fin"
            else:
                self._fin_close_pending = True

    def _update_bulk(self, direction: str, pi: _PacketInfo) -> None:
        if pi.payload_len <= 0:
            self._flush_bulk_run()
            return
        if direction != self._bulk_dir or (pi.ts - self._bulk_last_ts) > _BULK_MAX_GAP_S:
            self._flush_bulk_run()
            self._bulk_dir       = direction
            self._bulk_run_start = pi.ts
            self._bulk_run_pkts  = 0
            self._bulk_run_bytes = 0
        self._bulk_run_pkts  += 1
        self._bulk_run_bytes += pi.length
        self._bulk_last_ts    = pi.ts

    def _flush_bulk_run(self) -> None:
        if self._bulk_dir and self._bulk_run_pkts >= _BULK_MIN_PKTS:
            duration = max(self._bulk_last_ts - self._bulk_run_start, 1e-6)
            if self._bulk_dir == "fwd":
                self.fwd_bulk_bytes.append(self._bulk_run_bytes)
                self.fwd_bulk_pkts.append(self._bulk_run_pkts)
                self.fwd_bulk_durations.append(duration)
            else:
                self.bwd_bulk_bytes.append(self._bulk_run_bytes)
                self.bwd_bulk_pkts.append(self._bulk_run_pkts)
                self.bwd_bulk_durations.append(duration)
        self._bulk_dir       = None
        self._bulk_run_pkts  = 0
        self._bulk_run_bytes = 0

    def to_row(self) -> dict:
        """Finalize this flow into one CIC-IDS-schema record. Call exactly
        once, when the flow is closing (RST/FIN match, idle timeout, or
        forced flush) — mutates internal state (flushes the pending bulk
        run, closes the final active segment)."""
        self._flush_bulk_run()
        self.active_periods.append(self.last_ts - self._active_start)

        duration_s  = max(self.last_ts - self.first_ts, 0.0)
        duration_us = duration_s * 1_000_000.0

        fwd_len = np.array(self.fwd_lengths, dtype=float)
        bwd_len = np.array(self.bwd_lengths, dtype=float)
        all_len = np.concatenate([fwd_len, bwd_len]) if (len(fwd_len) or len(bwd_len)) else np.array([0.0])

        flow_iat = np.diff(np.sort(np.array(self.all_ts)) * 1_000_000.0) if len(self.all_ts) > 1 else np.array([])
        fwd_iat  = np.diff(np.array(self.fwd_ts) * 1_000_000.0) if len(self.fwd_ts) > 1 else np.array([])
        bwd_iat  = np.diff(np.array(self.bwd_ts) * 1_000_000.0) if len(self.bwd_ts) > 1 else np.array([])

        n_fwd, n_bwd = len(fwd_len), len(bwd_len)
        total_fwd_bytes = float(fwd_len.sum()) if n_fwd else 0.0
        total_bwd_bytes = float(bwd_len.sum()) if n_bwd else 0.0
        total_bytes = total_fwd_bytes + total_bwd_bytes
        total_pkts  = n_fwd + n_bwd

        return {
            "src_ip":                 self.src_ip,
            "dst_ip":                 self.dst_ip,
            "src_port":               self.src_port,
            "protocol":               self.proto,
            "destination_port":       self.dst_port,
            "flow_duration":          duration_us,
            "total_fwd_packets":      n_fwd,
            "total_backward_packets": n_bwd,
            "total_length_of_fwd_packets": total_fwd_bytes,
            "total_length_of_bwd_packets": total_bwd_bytes,
            "fwd_packet_length_max":  float(fwd_len.max())  if n_fwd else 0.0,
            "fwd_packet_length_min":  float(fwd_len.min())  if n_fwd else 0.0,
            "fwd_packet_length_mean": float(fwd_len.mean()) if n_fwd else 0.0,
            "fwd_packet_length_std":  float(fwd_len.std())  if n_fwd else 0.0,
            "bwd_packet_length_max":  float(bwd_len.max())  if n_bwd else 0.0,
            "bwd_packet_length_min":  float(bwd_len.min())  if n_bwd else 0.0,
            "bwd_packet_length_mean": float(bwd_len.mean()) if n_bwd else 0.0,
            "bwd_packet_length_std":  float(bwd_len.std())  if n_bwd else 0.0,
            "flow_bytes_per_s":   total_bytes / duration_s if duration_s > 0 else 0.0,
            "flow_packets_per_s": total_pkts  / duration_s if duration_s > 0 else 0.0,
            "flow_iat_mean": float(flow_iat.mean()) if len(flow_iat) else 0.0,
            "flow_iat_std":  float(flow_iat.std())  if len(flow_iat) else 0.0,
            "flow_iat_max":  float(flow_iat.max())  if len(flow_iat) else 0.0,
            "flow_iat_min":  float(flow_iat.min())  if len(flow_iat) else 0.0,
            "fwd_iat_total": float(fwd_iat.sum())  if len(fwd_iat) else 0.0,
            "fwd_iat_mean":  float(fwd_iat.mean()) if len(fwd_iat) else 0.0,
            "fwd_iat_std":   float(fwd_iat.std())  if len(fwd_iat) else 0.0,
            "fwd_iat_max":   float(fwd_iat.max())  if len(fwd_iat) else 0.0,
            "fwd_iat_min":   float(fwd_iat.min())  if len(fwd_iat) else 0.0,
            "bwd_iat_total": float(bwd_iat.sum())  if len(bwd_iat) else 0.0,
            "bwd_iat_mean":  float(bwd_iat.mean()) if len(bwd_iat) else 0.0,
            "bwd_iat_std":   float(bwd_iat.std())  if len(bwd_iat) else 0.0,
            "bwd_iat_max":   float(bwd_iat.max())  if len(bwd_iat) else 0.0,
            "bwd_iat_min":   float(bwd_iat.min())  if len(bwd_iat) else 0.0,
            "fwd_psh_flags": self.fwd_psh,
            "bwd_psh_flags": self.bwd_psh,
            "fwd_urg_flags": self.fwd_urg,
            "bwd_urg_flags": self.bwd_urg,
            "fwd_header_length": self.fwd_header_bytes,
            "bwd_header_length": self.bwd_header_bytes,
            "fwd_packets_per_s": n_fwd / duration_s if duration_s > 0 else 0.0,
            "bwd_packets_per_s": n_bwd / duration_s if duration_s > 0 else 0.0,
            "min_packet_length":      float(all_len.min()),
            "max_packet_length":      float(all_len.max()),
            "packet_length_mean":     float(all_len.mean()),
            "packet_length_std":      float(all_len.std()),
            "packet_length_variance": float(all_len.var()),
            "fin_flag_count": self.flag_counts["fin"],
            "syn_flag_count": self.flag_counts["syn"],
            "rst_flag_count": self.flag_counts["rst"],
            "psh_flag_count": self.flag_counts["psh"],
            "ack_flag_count": self.flag_counts["ack"],
            "urg_flag_count": self.flag_counts["urg"],
            "cwe_flag_count": self.flag_counts["cwe"],
            "ece_flag_count": self.flag_counts["ece"],
            "down_per_up_ratio":   (n_bwd / n_fwd) if n_fwd > 0 else 0.0,
            "average_packet_size": total_bytes / total_pkts if total_pkts > 0 else 0.0,
            # avg_{fwd,bwd}_segment_size duplicate {fwd,bwd}_packet_length_mean in the
            # original CICFlowMeter output — reproduced verbatim, not a bug.
            "avg_fwd_segment_size": float(fwd_len.mean()) if n_fwd else 0.0,
            "avg_bwd_segment_size": float(bwd_len.mean()) if n_bwd else 0.0,
            # "Fwd Header Length.1" is a duplicate column from the original CIC-IDS-2017
            # CSV (a repeated header pandas auto-suffixed on read) that survived into
            # training — emit it as a copy rather than let it get zero-filled.
            "Fwd Header Length.1": self.fwd_header_bytes,
            "fwd_avg_bytes_per_bulk":   self._bulk_avg(self.fwd_bulk_bytes),
            "fwd_avg_packets_per_bulk": self._bulk_avg(self.fwd_bulk_pkts),
            "fwd_avg_bulk_rate":        self._bulk_rate(self.fwd_bulk_bytes, self.fwd_bulk_durations),
            "bwd_avg_bytes_per_bulk":   self._bulk_avg(self.bwd_bulk_bytes),
            "bwd_avg_packets_per_bulk": self._bulk_avg(self.bwd_bulk_pkts),
            "bwd_avg_bulk_rate":        self._bulk_rate(self.bwd_bulk_bytes, self.bwd_bulk_durations),
            "subflow_fwd_packets": n_fwd / self.n_active_segments,
            "subflow_fwd_bytes":   total_fwd_bytes / self.n_active_segments,
            "subflow_bwd_packets": n_bwd / self.n_active_segments,
            "subflow_bwd_bytes":   total_bwd_bytes / self.n_active_segments,
            "init_win_bytes_forward":  self.init_win_fwd or 0,
            "init_win_bytes_backward": self.init_win_bwd or 0,
            "act_data_pkt_fwd":     self.act_data_pkt_fwd,
            "min_seg_size_forward": self.min_seg_size_fwd or 0,
            "active_mean": float(np.mean(self.active_periods)) * 1e6 if self.active_periods else 0.0,
            "active_std":  float(np.std(self.active_periods))  * 1e6 if self.active_periods else 0.0,
            "active_max":  float(np.max(self.active_periods))  * 1e6 if self.active_periods else 0.0,
            "active_min":  float(np.min(self.active_periods))  * 1e6 if self.active_periods else 0.0,
            "idle_mean": float(np.mean(self.idle_periods)) * 1e6 if self.idle_periods else 0.0,
            "idle_std":  float(np.std(self.idle_periods))  * 1e6 if self.idle_periods else 0.0,
            "idle_max":  float(np.max(self.idle_periods))  * 1e6 if self.idle_periods else 0.0,
            "idle_min":  float(np.min(self.idle_periods))  * 1e6 if self.idle_periods else 0.0,
            # For Layer 2 signature matching (detection/layer2_signatures.py)
            # — not a numeric feature, automatically excluded from every
            # ML/ANOVA feature path via their existing select_dtypes(number)
            # filters. Best-effort decode; injection/XSS patterns are ASCII.
            "payload_sample": self.payload_sample.decode("utf-8", errors="replace"),
        }

    @staticmethod
    def _bulk_avg(values: List[int]) -> float:
        return float(np.mean(values)) if values else 0.0

    @staticmethod
    def _bulk_rate(byte_values: List[int], durations: List[float]) -> float:
        if not byte_values:
            return 0.0
        total_time = sum(durations) or 1e-6
        return float(sum(byte_values) / total_time)


class FlowCollector:
    """
    Assembles raw Scapy packets into bidirectional flow records matching the
    CIC-IDS feature schema MLDetectionLayer.predict_chunk() expects (all 78
    raw columns — apply core.features.NetworkFeatureEngineer.transform() on
    this collector's output before inference to add bytes_per_pkt).

    Thread-safety: ingest_packet() is expected to run on the capture thread
    (e.g. AsyncSniffer's prn callback); pop_completed_flows(),
    sweep_idle_flows(), and flush_all() are expected to run on the main
    thread. All access to the flow table is guarded by a lock, mirroring
    the pattern used in forensics/packet_logger.py.

    Parameters:
        active_timeout_s — inter-packet gap (seconds) beyond which a new
                            "active period" starts, for active/idle stats.
        idle_timeout_s    — time since last packet after which an open flow
                            is force-closed by sweep_idle_flows().
        max_open_flows    — safety cap; oldest open flow is evicted (and
                            emitted) when this is exceeded.

    Usage:
        collector = FlowCollector()
        sniffer = AsyncSniffer(iface=iface, prn=collector.ingest_packet, store=False)
        sniffer.start()
        ...
        df = collector.pop_completed_flows()
    """

    def __init__(
        self,
        active_timeout_s: float = FLOW_ACTIVE_TIMEOUT_S,
        idle_timeout_s:   float = FLOW_IDLE_TIMEOUT_S,
        max_open_flows:   int   = FLOW_MAX_OPEN,
    ) -> None:
        self._active_timeout = active_timeout_s
        self._idle_timeout   = idle_timeout_s
        self._max_open       = max_open_flows

        self._flows: Dict[FlowKey, _FlowState] = {}
        self._creation_order: List[FlowKey] = []
        self._completed: List[dict] = []
        self._lock = threading.Lock()

        # (src_ip, dst_ip) -> deque of (timestamp, dst_port) per connection,
        # for cross-flow beacon detection (see _BEACON_* constants /
        # beacon_score()) and DoS/DDoS flood detection (see _DOS_*
        # constants / connection_rate()). dst_port is tracked alongside the
        # timestamp so connection_rate() can tell a real flood (many
        # connections, one hammered port) from a port scan (many
        # connections, many different ports) -- both have the same raw
        # connection *rate*, confirmed live 2026-08-24 when a fast nmap
        # scan's PortScan label got silently overridden to DoS on most of
        # its flows because rate alone couldn't distinguish them.
        self._conn_history: Dict[Tuple[str, str], deque] = defaultdict(
            lambda: deque(maxlen=_BEACON_HISTORY_LEN)
        )

        self._n_packets_seen     = 0
        self._n_flows_completed  = 0
        self._n_flows_evicted    = 0

        logger.info(
            "FlowCollector ready — active_timeout=%.1fs idle_timeout=%.1fs max_open=%d",
            active_timeout_s, idle_timeout_s, max_open_flows,
        )

    def ingest_packet(self, pkt) -> None:
        """Feed one raw Scapy packet. Safe to call from the capture thread."""
        try:
            pi = _parse_packet(pkt)
        except Exception as exc:
            logger.debug("Packet parse error: %s", exc)
            return
        if pi is None:
            return

        self._n_packets_seen += 1
        key = _canonical_key(pi)

        with self._lock:
            state = self._flows.get(key)

            # A fresh SYN (SYN set, ACK not set) on a 5-tuple that already
            # has an open flow means the OS reused this port for a new
            # connection while the old one never got a proper close (e.g. a
            # flood/scan packet that got no RST/FIN response, common under
            # sustained attack traffic). Without this, the new connection's
            # packets silently merge into the stale flow's accumulated
            # state — confirmed in the M5 lab capture: a real HTTP request
            # landed on a port an hping3 flood packet had used 215s earlier,
            # and its payload was lost because payload_sample's first-write
            # -wins rule had already been claimed by the ancient flow.
            # Gated on idle time so a legitimate rapid SYN retransmission
            # (RTO is normally >=1s) during an in-progress handshake isn't
            # mistaken for a new connection and split into two flow rows.
            is_new_syn = bool(pi.tcp_flags & _SYN) and not (pi.tcp_flags & _ACK)
            if state is not None and is_new_syn and pi.ts - state.last_ts > _SYN_REUSE_IDLE_S:
                state.closed_by = "reused_port"
                self._completed.append(state.to_row())
                self._n_flows_completed += 1
                del self._flows[key]
                self._creation_order.remove(key)
                state = None

            if state is None:
                if len(self._flows) >= self._max_open:
                    self._evict_oldest_locked()
                state = _FlowState(pi)
                self._flows[key] = state
                self._creation_order.append(key)
                self._conn_history[(pi.src_ip, pi.dst_ip)].append((pi.ts, pi.dst_port))
            else:
                state.ingest(pi)

            if state.closed_by in ("rst", "fin"):
                self._completed.append(state.to_row())
                self._n_flows_completed += 1
                del self._flows[key]
                self._creation_order.remove(key)

    def _evict_oldest_locked(self) -> None:
        """Force-close the oldest open flow. Caller must hold self._lock."""
        if not self._creation_order:
            return
        key = self._creation_order.pop(0)
        state = self._flows.pop(key, None)
        if state is not None:
            state.closed_by = "evicted"
            self._completed.append(state.to_row())
            self._n_flows_evicted += 1
            logger.debug("FlowCollector: evicted oldest open flow (max_open reached)")

    def pop_completed_flows(self) -> pd.DataFrame:
        """Drain flows closed by a TCP RST or matched FIN/FIN since the
        last call. Non-blocking; returns an empty DataFrame if none closed."""
        with self._lock:
            if not self._completed:
                return pd.DataFrame()
            rows, self._completed = self._completed, []
        return pd.DataFrame(rows)

    def sweep_idle_flows(self) -> pd.DataFrame:
        """Force-close open flows that have been quiet past idle_timeout_s.
        Call periodically from the main thread — handles UDP and any TCP
        flow that never cleanly closes."""
        now = time.time()
        closed_rows: List[dict] = []
        with self._lock:
            stale_keys = [
                key for key, state in self._flows.items()
                if now - state.last_ts > self._idle_timeout
            ]
            for key in stale_keys:
                state = self._flows.pop(key)
                self._creation_order.remove(key)
                state.closed_by = "idle"
                closed_rows.append(state.to_row())
                self._n_flows_completed += 1
        return pd.DataFrame(closed_rows)

    def flush_all(self) -> pd.DataFrame:
        """Force-close every open flow, plus drain any already-completed
        flows not yet popped. Call on shutdown."""
        with self._lock:
            rows = [state.to_row() for state in self._flows.values()]
            self._n_flows_completed += len(rows)
            self._flows.clear()
            self._creation_order.clear()
            pending, self._completed = self._completed, []
        return pd.DataFrame(pending + rows)

    def get_stats(self) -> dict:
        """Return cumulative collector statistics since instantiation."""
        with self._lock:
            open_flows = len(self._flows)
        return {
            "packets_seen":    self._n_packets_seen,
            "open_flows":      open_flows,
            "flows_completed": self._n_flows_completed,
            "flows_evicted":   self._n_flows_evicted,
        }

    def beacon_score(self, src_ip: str, dst_ip: str) -> dict:
        """
        Cross-flow connection-regularity signal for one (src_ip, dst_ip)
        pair, for Bot/C2 beacon detection (see _BEACON_* constants above).

        Inputs:  src_ip, dst_ip — the pair to score
        Outputs: dict with conn_count, is_beacon (bool), interval_cv
                 (coefficient of variation of inter-connection intervals,
                 None if not enough history), mean_interval_s
        """
        with self._lock:
            raw_history = list(self._conn_history.get((src_ip, dst_ip), ()))
        history = [ts for ts, _port in raw_history]

        if len(history) < _BEACON_MIN_CONNECTIONS:
            return {"conn_count": len(history), "is_beacon": False,
                    "interval_cv": None, "mean_interval_s": None}

        intervals = [b - a for a, b in zip(history, history[1:])]
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < _BEACON_MIN_MEAN_INTERVAL_S:
            # Too fast to be a beacon regardless of regularity -- a port
            # scan's evenly-paced probes look just as low-variance as a
            # genuine beacon, only on a millisecond timescale instead of
            # seconds-to-minutes. See _BEACON_MIN_MEAN_INTERVAL_S's comment.
            return {"conn_count": len(history), "is_beacon": False,
                    "interval_cv": None, "mean_interval_s": round(mean_interval, 4)}

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        cv = (variance ** 0.5) / mean_interval
        is_beacon = cv <= _BEACON_MAX_CV
        return {"conn_count": len(history), "is_beacon": is_beacon,
                "interval_cv": round(cv, 4), "mean_interval_s": round(mean_interval, 2)}

    def connection_rate(self, src_ip: str, dst_ip: str) -> dict:
        """
        Cross-flow connection-rate signal for one (src_ip, dst_ip) pair,
        for DoS/DDoS flood detection (see _DOS_* constants above).

        Inputs:  src_ip, dst_ip — the pair to score
        Outputs: dict with conn_count, is_flood (bool), rate_per_sec
                 (float, None if fewer than _DOS_MIN_CONNECTIONS
                 connections recorded), port_concentration (share of
                 connections hitting the single most-hit port, None if not
                 enough history)
        """
        with self._lock:
            history = list(self._conn_history.get((src_ip, dst_ip), ()))

        if len(history) < _DOS_MIN_CONNECTIONS:
            return {"conn_count": len(history), "is_flood": False,
                    "rate_per_sec": None, "port_concentration": None}

        timestamps = [ts for ts, _port in history]
        ports      = [port for _ts, port in history]

        span = timestamps[-1] - timestamps[0]
        rate = float(len(timestamps)) if span <= 0 else (len(timestamps) - 1) / span

        # A real flood hammers one service (one port); a port scan probes
        # many different ports on the same host at a similarly high rate --
        # rate alone can't tell them apart. Require the connections to be
        # concentrated on a small set of ports before calling it a flood;
        # a scan's port diversity keeps its port_concentration low and
        # leaves it for Layer 1's own PortScan classification instead.
        port_concentration = Counter(ports).most_common(1)[0][1] / len(ports)
        is_flood = (rate >= _DOS_RATE_THRESHOLD_PER_S
                    and port_concentration >= _DOS_MIN_PORT_CONCENTRATION)
        return {"conn_count": len(history), "is_flood": is_flood,
                "rate_per_sec": round(rate, 2),
                "port_concentration": round(port_concentration, 2)}
