"""Isolation Forest wrapper for sparse anomaly detection."""

import numpy as np
from typing import Optional
from sklearn.ensemble import IsolationForest as SklearnIsolationForest


class IsolationForestDetector:
    """
    Wrapper around scikit-learn's IsolationForest.
    Detects sparse anomalies by isolating outliers via random partitioning.

    The anomaly score is the negative of the decision function
    (more negative = more anomalous). We invert it so higher = more anomalous,
    consistent with the autoencoder's convention.
    """

    def __init__(
        self,
        n_estimators: int = 200,
        max_samples: float = 0.1,
        contamination: float = 0.001,
        random_state: int = 42,
        n_jobs: int = -1,
    ):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self.n_jobs = n_jobs
        self._model: Optional[SklearnIsolationForest] = None

    def fit(self, X: np.ndarray):
        """Train the Isolation Forest on normal traffic data."""
        self._model = SklearnIsolationForest(
            n_estimators=self.n_estimators,
            max_samples=min(self.max_samples, 1.0),
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
        )
        self._model.fit(X)
        return self

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """
        Compute anomaly scores.
        Returns higher scores for more anomalous samples.
        """
        if self._model is None:
            raise RuntimeError("Model not fitted. Call fit() first.")
        scores = self._model.decision_function(X)
        # Invert so higher = more anomalous
        return -scores

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return binary labels: 1 = anomaly, 0 = normal."""
        if self._model is None:
            raise RuntimeError("Model not fitted. Call fit() first.")
        raw = self._model.predict(X)
        # Convert: sklearn returns -1 for anomaly, 1 for normal
        return np.where(raw == -1, 1, 0)

    def save(self, path: str):
        """Serialize model."""
        import joblib
        if self._model is not None:
            joblib.dump(self._model, path)

    def load(self, path: str):
        """Deserialize model."""
        import joblib
        self._model = joblib.load(path)

    @property
    def is_fitted(self) -> bool:
        return self._model is not None