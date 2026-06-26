"""Feature normalizer — Z-score / MinMax scaling for ML models."""

import numpy as np
from typing import Optional, List, Tuple


class FeatureNormalizer:
    """
    Normalizes feature vectors using either Z-score or MinMax scaling.
    Fits statistics on training data, then transforms live features.

    Usage:
        normalizer = FeatureNormalizer(method="zscore")
        normalizer.fit(training_features)  # np.ndarray of shape (N, D)
        normalized = normalizer.transform(live_features)
    """

    def __init__(self, method: str = "zscore", input_dim: int = 128):
        assert method in ("zscore", "minmax"), "Method must be 'zscore' or 'minmax'"
        self.method = method
        self.input_dim = input_dim
        self._mean: Optional[np.ndarray] = None
        self._std: Optional[np.ndarray] = None
        self._min: Optional[np.ndarray] = None
        self._max: Optional[np.ndarray] = None
        self._fitted = False

    def fit(self, features: np.ndarray):
        """Compute normalization statistics from training data."""
        if features.shape[1] != self.input_dim:
            raise ValueError(
                f"Expected input_dim={self.input_dim}, got {features.shape[1]}"
            )

        if self.method == "zscore":
            self._mean = np.mean(features, axis=0)
            self._std = np.std(features, axis=0)
            self._std[self._std == 0] = 1.0  # Avoid division by zero
        else:
            self._min = np.min(features, axis=0)
            self._max = np.max(features, axis=0)
            ranges = self._max - self._min
            ranges[ranges == 0] = 1.0  # Avoid division by zero
            self._max = self._min + ranges  # Store adjusted max

        self._fitted = True

    def transform(self, features: np.ndarray) -> np.ndarray:
        """Apply normalization to feature vectors."""
        if not self._fitted:
            raise RuntimeError("Normalizer not fitted. Call fit() first.")

        if self.method == "zscore":
            return (features - self._mean) / self._std
        else:
            return (features - self._min) / (self._max - self._min)

    def fit_transform(self, features: np.ndarray) -> np.ndarray:
        """Fit and transform in one call."""
        self.fit(features)
        return self.transform(features)

    def inverse_transform(self, features: np.ndarray) -> np.ndarray:
        """Reverse normalization (useful for reconstruction error analysis)."""
        if not self._fitted:
            raise RuntimeError("Normalizer not fitted. Call fit() first.")

        if self.method == "zscore":
            return features * self._std + self._mean
        else:
            return features * (self._max - self._min) + self._min

    def save_stats(self) -> dict:
        """Return statistics dict for serialization."""
        if not self._fitted:
            return {"method": self.method, "input_dim": self.input_dim, "fitted": False}

        stats = {
            "method": self.method,
            "input_dim": self.input_dim,
            "fitted": True,
        }
        if self.method == "zscore":
            stats["mean"] = self._mean.tolist()
            stats["std"] = self._std.tolist()
        else:
            stats["min"] = self._min.tolist()
            stats["max"] = self._max.tolist()
        return stats

    def load_stats(self, stats: dict):
        """Restore statistics from dict."""
        self.method = stats["method"]
        self.input_dim = stats["input_dim"]
        if stats.get("fitted", False):
            if self.method == "zscore":
                self._mean = np.array(stats["mean"])
                self._std = np.array(stats["std"])
            else:
                self._min = np.array(stats["min"])
                self._max = np.array(stats["max"])
            self._fitted = True