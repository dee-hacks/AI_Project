"""Per-packet feature extraction functions."""

import math
from typing import Dict, Any, List
from hashlib import md5


def extract_per_packet_features(packet: Dict[str, Any]) -> List[float]:
    """
    Extract a fixed-size feature vector from a single parsed packet.
    Returns a list of 32 features (float).

    Features:
      [0]  protocol (1=ICMP, 6=TCP, 17=UDP, else 0)
      [1]  src_ip hash (first 2 bytes of MD5 → [0,1])
      [2]  dst_ip hash (first 2 bytes of MD5 → [0,1])
      [3]  sport (normalized / 65535)
      [4]  dport (normalized / 65535)
      [5]  packet_len (log-scaled)
      [6]  ttl (normalized / 255)
      [7]  payload_len (log-scaled)
      [8]  payload_entropy (0-8 range, normalized / 8)
      [9]  tcp_flags (if TCP, else 0)
      [10] tcp_window (log-scaled, if TCP else 0)
      [11] udp_len (normalized / 65535, if UDP else 0)
      [12] icmp_type (if ICMP else 0)
      [13] icmp_code (if ICMP else 0)
      [14] ip_id (normalized / 65535)
      [15] ip_flags (0-7 range)
      [16] tcp_seq delta (placeholder 0 for single packet)
      [17] inter_arrival (0 for single packet)
      [18-31] reserved (zeros, for future use)
    """
    proto = packet.get("protocol", 0)
    proto_enc = 1.0 if proto == 1 else (6.0 if proto == 6 else (17.0 if proto == 17 else 0.0))

    src_hash = _ip_hash(packet.get("src_ip", "0.0.0.0"))
    dst_hash = _ip_hash(packet.get("dst_ip", "0.0.0.0"))

    features = [
        proto_enc / 17.0,  # normalize to [0,1]
        src_hash,
        dst_hash,
        packet.get("sport", 0) / 65535.0,
        packet.get("dport", 0) / 65535.0,
        _log_scale(packet.get("packet_len", 0), max_val=1500),
        packet.get("ttl", 64) / 255.0,
        _log_scale(packet.get("payload_len", 0), max_val=1460),
        (packet.get("payload_entropy", 0.0) / 8.0) if packet.get("payload_entropy", 0) > 0 else 0.0,
        float(packet.get("tcp_flags", 0)),
        _log_scale(packet.get("tcp_window", 0), max_val=65535),
        packet.get("udp_len", 0) / 65535.0,
        float(packet.get("icmp_type", 0)) / 255.0,
        float(packet.get("icmp_code", 0)) / 255.0,
        packet.get("ip_id", 0) / 65535.0,
        float(packet.get("ip_flags", 0)) / 7.0,
        0.0,  # tcp_seq delta placeholder
        0.0,  # inter_arrival placeholder
        0.0, 0.0, 0.0, 0.0, 0.0,
        0.0, 0.0, 0.0, 0.0, 0.0,
        0.0, 0.0, 0.0, 0.0,
    ]

    return features


def _ip_hash(ip: str) -> float:
    """Hash IP to a float in [0, 1]."""
    if not ip:
        return 0.0
    digest = md5(ip.encode()).digest()
    return (digest[0] * 256 + digest[1]) / 65535.0


def _log_scale(value: int, max_val: int = 1500, eps: float = 1.0) -> float:
    """Log-scale a value and normalize to [0, 1]."""
    if value <= 0:
        return 0.0
    return math.log1p(value) / math.log1p(max_val)