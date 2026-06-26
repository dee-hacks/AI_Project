"""Offline training pipeline for the anomaly detection ensemble."""

import numpy as np
from typing import Tuple, Optional
from sklearn.model_selection import train_test_split

from src.ai.autoencoder import AnomalyAutoencoder
from src.ai.isolation_forest import IsolationForestDetector
from src.ai.ensemble import AnomalyEnsemble
from src.ai.threshold import compute_threshold
from src.features.normalizer import FeatureNormalizer


class Trainer:
    """
    Orchestrates offline training of the full anomaly detection pipeline:
      1. Load and split feature data
      2. Fit normalizer
      3. Train autoencoder
      4. Train isolation forest
      5. Build ensemble
      6. Compute threshold
    """

    def __init__(
        self,
        input_dim: int = 128,
        ae_epochs: int = 50,
        ae_batch_size: int = 64,
        ae_lr: float = 1e-3,
        if_n_estimators: int = 200,
        if_max_samples: float = 0.1,
        if_contamination: float = 0.001,
        ensemble_ae_weight: float = 0.6,
        ensemble_if_weight: float = 0.4,
        threshold_percentile: float = 99.98,
        val_split: float = 0.2,
        random_state: int = 42,
    ):
        self.input_dim = input_dim
        self.ae_epochs = ae_epochs
        self.ae_batch_size = ae_batch_size
        self.ae_lr = ae_lr
        self.if_n_estimators = if_n_estimators
        self.if_max_samples = if_max_samples
        self.if_contamination = if_contamination
        self.ensemble_ae_weight = ensemble_ae_weight
        self.ensemble_if_weight = ensemble_if_weight
        self.threshold_percentile = threshold_percentile
        self.val_split = val_split
        self.random_state = random_state

        self.normalizer = FeatureNormalizer(method="zscore", input_dim=input_dim)
        self.autoencoder: Optional[AnomalyAutoencoder] = None
        self.isolation_forest: Optional[IsolationForestDetector] = None
        self.ensemble: Optional[AnomalyEnsemble] = None
        self.threshold: float = 0.0
        self.ae_history: list = []

    def train(self, features: np.ndarray) -> dict:
        """
        Run full training pipeline.

        Args:
            features: Raw feature matrix, shape (N, input_dim)

        Returns:
            Dict with training results and metrics
        """
        # 1. Split data
        X_train, X_val = train_test_split(
            features,
            test_size=self.val_split,
            random_state=self.random_state,
        )

        # 2. Fit normalizer
        X_train_norm = self.normalizer.fit_transform(X_train)
        X_val_norm = self.normalizer.transform(X_val)

        # 3. Train autoencoder
        print("Training autoencoder...")
        self.autoencoder, self.ae_history = AnomalyAutoencoder.create_and_train(
            train_data=X_train_norm,
            val_data=X_val_norm,
            input_dim=self.input_dim,
            epochs=self.ae_epochs,
            batch_size=self.ae_batch_size,
            learning_rate=self.ae_lr,
        )

        # 4. Train Isolation Forest
        print("Training Isolation Forest...")
        self.isolation_forest = IsolationForestDetector(
            n_estimators=self.if_n_estimators,
            max_samples=self.if_max_samples,
            contamination=self.if_contamination,
        )
        self.isolation_forest.fit(X_train_norm)

        # 5. Build ensemble
        print("Building ensemble...")
        self.ensemble = AnomalyEnsemble(
            ae_weight=self.ensemble_ae_weight,
            if_weight=self.ensemble_if_weight,
            threshold=1.0,  # Will be updated after threshold computation
        )
        self.ensemble.set_models(self.autoencoder, self.isolation_forest)

        # 6. Compute threshold on validation set
        _, val_scores = self.ensemble.predict(X_val_norm)
        self.threshold = compute_threshold(val_scores, self.threshold_percentile)
        self.ensemble.set_threshold(self.threshold)

        # Metrics
        val_anomaly_rate = float(np.mean(val_scores > self.threshold))
        print(f"Threshold (p{self.threshold_percentile}): {self.threshold:.6f}")
        print(f"Validation anomaly rate: {val_anomaly_rate*100:.4f}%")

        return {
            "threshold": self.threshold,
            "val_anomaly_rate": val_anomaly_rate,
            "ae_final_loss": self.ae_history[-1] if self.ae_history else None,
            "num_train_samples": len(X_train),
            "num_val_samples": len(X_val),
        }

    def save_all(self, ae_path: str, if_path: str, ensemble_path: str, normalizer_path: str):
        """Save all trained artifacts."""
        import json

        if self.autoencoder:
            self.autoencoder.save(ae_path)
        if self.isolation_forest:
            self.isolation_forest.save(if_path)
        if self.ensemble:
            self.ensemble.save(ae_path, if_path, ensemble_path)

        normalizer_stats = self.normalizer.save_stats()
        with open(normalizer_path, "w") as f:
            json.dump(normalizer_stats, f)

    def load_all(self, ae_path: str, if_path: str, ensemble_path: str, normalizer_path: str):
        """Load all trained artifacts."""
        import json

        self.autoencoder = AnomalyAutoencoder(input_dim=self.input_dim)
        self.autoencoder.load(ae_path)

        self.isolation_forest = IsolationForestDetector()
        self.isolation_forest.load(if_path)

        self.ensemble = AnomalyEnsemble()
        self.ensemble.load(ae_path, if_path, ensemble_path, self.input_dim)

        with open(normalizer_path, "r") as f:
            normalizer_stats = json.load(f)
        self.normalizer.load_stats(normalizer_stats)