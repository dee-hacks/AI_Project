"""Threshold calculator for anomaly detection."""

import numpy as np


def compute_threshold(
    scores: np.ndarray,
    percentile: float = 99.98,
) -> float:
    """
    Compute anomaly threshold as a high percentile of training scores.
    At p=99.98, expect ~0.02% FP rate on training data.

    Args:
        scores: Array of anomaly scores from training data
        percentile: Percentile to use as threshold (default 99.98)

    Returns:
        Threshold value. Scores above this are considered anomalous.
    """
    if len(scores) == 0:
        raise ValueError("Empty scores array")
    return float(np.percentile(scores, percentile))


def estimate_contamination(
    scores: np.ndarray,
    threshold: float,
) -> float:
    """
    Estimate the contamination ratio (fraction of anomalies) given a threshold.
    """
    if len(scores) == 0:
        return 0.0
    return float(np.mean(scores > threshold))