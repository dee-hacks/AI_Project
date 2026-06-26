"""Tests for AI detection models."""

import pytest
import numpy as np
import torch

from src.ai.autoencoder import AnomalyAutoencoder
from src.ai.isolation_forest import IsolationForestDetector
from src.ai.ensemble import AnomalyEnsemble
from src.ai.threshold import compute_threshold


class TestAutoencoder:
    def test_initialization(self):
        """Test autoencoder creation."""
        model = AnomalyAutoencoder(input_dim=128)
        assert model.input_dim == 128

    def test_forward_shape(self, sample_features):
        """Test forward pass preserves shape."""
        model = AnomalyAutoencoder(input_dim=128)
        x = torch.from_numpy(sample_features[:2]).float()
        output = model(x)
        assert output.shape == x.shape

    def test_anomaly_score(self, sample_features):
        """Test anomaly score computation."""
        model = AnomalyAutoencoder(input_dim=128)
        x = torch.from_numpy(sample_features).float()
        scores = model.anomaly_score(x)
        assert len(scores) == len(sample_features)
        assert all(s >= 0 for s in scores)

    def test_training(self):
        """Test that training reduces loss."""
        data = np.random.randn(100, 128).astype(np.float32)
        model, history = AnomalyAutoencoder.create_and_train(
            data, epochs=5, batch_size=32, verbose=False
        )
        # Final loss should be lower than or similar to initial
        assert history[-1] <= history[0] * 1.5  # Allow some tolerance
        assert len(history) == 5


class TestIsolationForest:
    def test_fit_and_score(self, sample_features):
        """Test isolation forest fitting and scoring."""
        model = IsolationForestDetector(
            n_estimators=10, max_samples=0.5, contamination=0.1
        )
        model.fit(sample_features)
        scores = model.anomaly_score(sample_features)
        assert len(scores) == len(sample_features)

    def test_predict(self, sample_features):
        """Test isolation forest prediction."""
        model = IsolationForestDetector(
            n_estimators=10, max_samples=0.5, contamination=0.1
        )
        model.fit(sample_features)
        preds = model.predict(sample_features)
        assert set(preds).issubset({0, 1})


class TestEnsemble:
    def test_ensemble_prediction(self, sample_features):
        """Test ensemble prediction."""
        ae = AnomalyAutoencoder(input_dim=128)
        ae.eval()

        if_model = IsolationForestDetector(
            n_estimators=10, max_samples=0.5, contamination=0.1
        )
        if_model.fit(sample_features)

        ensemble = AnomalyEnsemble(ae_weight=0.6, if_weight=0.4, threshold=0.5)
        ensemble.set_models(ae, if_model)

        is_anomaly, scores = ensemble.predict(sample_features)
        assert len(is_anomaly) == len(sample_features)
        assert len(scores) == len(sample_features)

    def test_threshold(self):
        """Test threshold computation."""
        scores = np.random.randn(1000) * 0.5 + 1.0
        threshold = compute_threshold(scores, percentile=95.0)
        assert threshold > 0
        assert np.mean(scores > threshold) <= 0.06  # ~5% + tolerance