"""Flow-level feature extraction with sliding window aggregates."""

import time
from collections import defaultdict, deque
from typing import Dict, Any, List, Tuple
from hashlib import md5

import numpy as np


class FlowFeatureExtractor:
    """
    Computes flow-level features over a sliding time window.
    Maintains per-flow state and produces aggregate feature vectors.

    A "flow" is defined as (src_ip, dst_ip, src_port, dst_port, protocol).
    """

    def __init__(self, window_sec: float = 1.0, max_flows: int = 10000):
        self.window_sec = window_sec
        self.max_flows = max_flows
        # flow_key → deque of (timestamp, packet_len, sport, dport)
        self._flow_buffers: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        self._flow_first_seen: Dict[str, float] = {}
        self._prev_timestamps: Dict[str, float] = {}

    def extract_flow_features(self, packet: Dict[str, Any]) -> List[float]:
        """
        Extract flow-level features for a single packet.
        Returns 32 features that complement per_packet features.

        Features:
          [0]  packets_in_window (count)
          [1]  bytes_in_window (sum, log-scaled)
          [2]  unique_dports in window (entropy-like)
          [3]  flow_duration (seconds from first packet)
          [4]  packet_rate (packets/sec in window)
          [5]  byte_rate (bytes/sec log-scaled)
          [6]  avg_packet_size in window
          [7]  std_packet_size in window
          [8]  syn_flag_ratio in window
          [9]  ack_flag_ratio in window
          [10] inter_arrival_time_avg
          [11] inter_arrival_time_std
          [12] burst_count (>1 packet in 10ms)
          [13] flow_bytes_per_sec (log-scaled)
          [14] port_entropy (sports in window)
          [15-31] reserved (zeros)

        Returns a full 32-length vector (suitable for concatenation).
        """
        flow_key = self._make_flow_key(packet)
        now = packet.get("timestamp", time.time())
        pkt_len = packet.get("packet_len", 0)
        sport = packet.get("sport", 0)

        # Store packet in flow buffer
        self._flow_buffers[flow_key].append((now, pkt_len, sport))

        # Track first seen
        if flow_key not in self._flow_first_seen:
            self._flow_first_seen[flow_key] = now

        # Prune old flows if we exceed max_flows
        if len(self._flow_buffers) > self.max_flows:
            self._prune_old_flows()

        # Get window data
        window_start = now - self.window_sec
        window_packets = [
            p for p in self._flow_buffers[flow_key]
            if p[0] >= window_start
        ]

        if len(window_packets) < 2:
            # Not enough data for meaningful flow features
            flow_duration = now - self._flow_first_seen.get(flow_key, now)
            base_features = [
                float(len(window_packets)),  # count
                _log_scale(sum(p[1] for p in window_packets), max_val=65535),  # bytes
                0.0,  # dport entropy
                flow_duration,
                0.0,  # pkt rate
                0.0,  # byte rate
                0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            ]
        else:
            flow_duration = now - self._flow_first_seen.get(flow_key, now)
            pkt_lens = np.array([p[1] for p in window_packets])
            timestamps = np.array([p[0] for p in window_packets])
            inter_arrivals = np.diff(timestamps)
            sports_in_window = [p[2] for p in window_packets]

            # SYN/ACK flag detection (derived from sport parity heuristic)
            syn_ratio = np.mean([
                1.0 for p in window_packets
                if p[2] < 1024  # heuristic: low sport = syn-like
            ]) if window_packets else 0.0

            base_features = [
                float(len(window_packets)),
                _log_scale(int(pkt_lens.sum()), max_val=65535),
                _port_entropy(sports_in_window),
                flow_duration,
                len(window_packets) / max(self.window_sec, 0.001),
                _log_scale(int(pkt_lens.sum() / max(self.window_sec, 0.001)), max_val=1000000),
                float(np.mean(pkt_lens)),
                float(np.std(pkt_lens)) if len(pkt_lens) > 1 else 0.0,
                syn_ratio,
                1.0 - syn_ratio,  # ack ratio heuristic
                float(np.mean(inter_arrivals)) if len(inter_arrivals) > 0 else 0.0,
                float(np.std(inter_arrivals)) if len(inter_arrivals) > 1 else 0.0,
                _count_bursts(timestamps),
                _log_scale(int(pkt_lens.sum() / max(flow_duration, 0.001)), max_val=1000000),
                _port_entropy([p[2] for p in window_packets]),
            ]

        # Pad to 32
        features = base_features + [0.0] * (32 - len(base_features))
        return features[:32]

    def _make_flow_key(self, packet: Dict[str, Any]) -> str:
        """Generate a unique flow key."""
        src = packet.get("src_ip", "0")
        dst = packet.get("dst_ip", "0")
        sp = packet.get("sport", 0)
        dp = packet.get("dport", 0)
        proto = packet.get("protocol", 0)
        return f"{src}:{sp}-{dst}:{dp}-{proto}"

    def _prune_old_flows(self):
        """Remove flows that haven't been active in 2 windows."""
        now = time.time()
        cutoff = now - 2 * self.window_sec
        stale = [
            k for k, buf in self._flow_buffers.items()
            if not buf or buf[-1][0] < cutoff
        ]
        for k in stale:
            del self._flow_buffers[k]
            self._flow_first_seen.pop(k, None)


def _log_scale(value: int, max_val: int = 1500, eps: float = 1.0) -> float:
    """Log-scale and normalize to [0, 1]."""
    if value <= 0:
        return 0.0
    import math
    return math.log1p(value) / math.log1p(max_val)


def _port_entropy(ports: List[int]) -> float:
    """Compute normalized entropy of port distribution."""
    if not ports:
        return 0.0
    from math import log2
    n = len(ports)
    counts = {}
    for p in ports:
        counts[p] = counts.get(p, 0) + 1
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * log2(p)
    max_entropy = log2(len(counts)) if len(counts) > 1 else 1.0
    return entropy / max_entropy if max_entropy > 0 else 0.0


def _count_bursts(timestamps: np.ndarray, threshold: float = 0.01) -> float:
    """Count the number of bursts (packets within threshold seconds)."""
    if len(timestamps) < 2:
        return 0.0
    diffs = np.diff(timestamps)
    return float(np.sum(diffs < threshold))