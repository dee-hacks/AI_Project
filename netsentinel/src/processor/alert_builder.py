"""Alert builder — enriches anomaly events with metadata and severity."""

import time
import uuid
from typing import Dict, Any


# Severity thresholds (multipliers of base threshold)
SEVERITY_CONFIG = {
    "low": {"min_multiplier": 0.5, "max_multiplier": 1.0},
    "medium": {"min_multiplier": 1.0, "max_multiplier": 2.0},
    "high": {"min_multiplier": 2.0, "max_multiplier": 3.0},
    "critical": {"min_multiplier": 3.0, "max_multiplier": float("inf")},
}


def build_alert(
    packet: Dict[str, Any],
    feature_vector: list,
    anomaly_score: float,
    threshold: float,
    detector: str = "ensemble",
) -> Dict[str, Any]:
    """
    Build a structured alert from an anomaly event.

    Args:
        packet: Original parsed packet dictionary
        feature_vector: The feature vector that triggered the alert
        anomaly_score: Ensemble anomaly score
        threshold: Detection threshold
        detector: Which detector flagged it

    Returns:
        Structured alert dictionary ready for storage and broadcast
    """
    severity = _classify_severity(anomaly_score, threshold)

    alert = {
        "alert_id": str(uuid.uuid4()),
        "timestamp": packet.get("timestamp", time.time()),
        "detector": detector,
        "anomaly_score": float(anomaly_score),
        "threshold": float(threshold),
        "severity": severity,
        "src_ip": packet.get("src_ip", "unknown"),
        "dst_ip": packet.get("dst_ip", "unknown"),
        "protocol": packet.get("protocol", 0),
        "sport": packet.get("sport", 0),
        "dport": packet.get("dport", 0),
        "packet_len": packet.get("packet_len", 0),
        "ttl": packet.get("ttl", 0),
        "tcp_flags": packet.get("tcp_flags", 0),
        "payload_entropy": packet.get("payload_entropy", 0.0),
        "feature_vector_sample": feature_vector[:10],  # First 10 dims for context
        "feature_vector_dim": len(feature_vector),
        "flow_key": f"{packet.get('src_ip', '?')}:{packet.get('sport', 0)}-"
                    f"{packet.get('dst_ip', '?')}:{packet.get('dport', 0)}",
        "status": "open",
        "acknowledged": False,
    }

    return alert


def _classify_severity(score: float, threshold: float) -> str:
    """Classify severity based on score vs threshold multiplier."""
    if threshold <= 0:
        return "medium"

    ratio = score / threshold

    for severity, config in SEVERITY_CONFIG.items():
        if config["min_multiplier"] <= ratio < config["max_multiplier"]:
            return severity

    return "critical"