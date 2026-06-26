"""Weighted ensemble: Autoencoder + Isolation Forest anomaly detection."""

import numpy as np
import torch
from typing import Tuple, Optional

from src.ai.autoencoder import AnomalyAutoencoder
from src.ai.isolation_forest import IsolationForestDetector


class AnomalyEnsemble:
    """
    Weighted ensemble combining autoencoder reconstruction error with
    Isolation Forest anomaly scores.

    Final score = w_ae * norm_ae_score + w_if * norm_if_score

    The ensemble reduces false positives by requiring consensus between
    a deep learning model (captures complex normal patterns) and a
    traditional ML model (good at sparse outlier detection).
    """

    def __init__(
        self,
        ae_weight: float = 0.6,
        if_weight: float = 0.4,
        threshold: float = 1.0,
    ):
        self.ae: Optional[AnomalyAutoencoder] = None
        self.if_model: Optional[IsolationForestDetector] = None
        self.weights = np.array([ae_weight, if_weight])
        self.threshold = threshold

    def set_models(
        self,
        autoencoder: AnomalyAutoencoder,
        isolation_forest: IsolationForestDetector,
    ):
        """Set the constituent models."""
        self.ae = autoencoder
        self.if_model = isolation_forest

    def predict(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies using the ensemble.

        Args:
            features: Normalized feature matrix, shape (N, D)

        Returns:
            Tuple of (is_anomaly_bool_array, ensemble_scores)
            - is_anomaly: bool array where True = anomaly
            - scores: float array of ensemble scores
        """
        if self.ae is None or self.if_model is None:
            raise RuntimeError("Models not set. Call set_models() first.")

        # Get scores from each model
        ae_scores = self.ae.anomaly_score(torch.from_numpy(features).float())
        if_scores = self.if_model.anomaly_score(features)

        # Normalize scores to [0, 1] for fair weighting
        ae_norm = _normalize(ae_scores)
        if_norm = _normalize(if_scores)

        # Weighted combination
        combined = self.weights[0] * ae_norm + self.weights[1] * if_norm

        return combined > self.threshold, combined

    def set_threshold(self, threshold: float):
        """Update detection threshold."""
        self.threshold = threshold

    def save(self, ae_path: str, if_path: str, stats_path: str):
        """Save all models and ensemble config."""
        if self.ae is not None:
            self.ae.save(ae_path)
        if self.if_model is not None:
            self.if_model.save(if_path)

        import json
        config = {
            "ae_weight": float(self.weights[0]),
            "if_weight": float(self.weights[1]),
            "threshold": float(self.threshold),
        }
        with open(stats_path, "w") as f:
            json.dump(config, f)

    def load(self, ae_path: str, if_path: str, stats_path: str, input_dim: int = 128):
        """Load all models and config."""
        self.ae = AnomalyAutoencoder(input_dim=input_dim)
        self.ae.load(ae_path)

        self.if_model = IsolationForestDetector()
        self.if_model.load(if_path)

        import json
        with open(stats_path, "r") as f:
            config = json.load(f)
        self.weights = np.array([config["ae_weight"], config["if_weight"]])
        self.threshold = config["threshold"]


def _normalize(scores: np.ndarray) -> np.ndarray:
    """Min-max normalize to [0, 1]."""
    s_min = scores.min()
    s_max = scores.max()
    if s_max - s_min < 1e-8:
        return np.zeros_like(scores)
    return (scores - s_min) / (s_max - s_min)