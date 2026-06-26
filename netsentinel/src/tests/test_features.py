"""Tests for feature extraction."""

import pytest
import numpy as np
from src.features.per_packet import extract_per_packet_features
from src.features.flow_features import FlowFeatureExtractor
from src.features.normalizer import FeatureNormalizer


class TestPerPacketFeatures:
    def test_extract_tcp_features(self, sample_packet_tcp):
        """Test feature extraction from a TCP packet."""
        features = extract_per_packet_features(sample_packet_tcp)
        assert len(features) == 32
        assert all(isinstance(f, float) for f in features)
        # Protocol should be TCP (6/17 ≈ 0.35)
        assert 0.3 <= features[0] <= 0.4

    def test_extract_udp_features(self, sample_packet_udp):
        """Test feature extraction from a UDP packet."""
        features = extract_per_packet_features(sample_packet_udp)
        assert len(features) == 32
        assert all(0.0 <= f <= 1.0 for f in features if f > 0)

    def test_feature_range(self, sample_packet_tcp):
        """Test that all features are in [0, 1]."""
        features = extract_per_packet_features(sample_packet_tcp)
        for i, f in enumerate(features):
            assert 0.0 <= f <= 1.0, f"Feature {i} out of range: {f}"


class TestFlowFeatures:
    def test_single_packet_flow(self, sample_packet_tcp):
        """Test flow features with a single packet."""
        extractor = FlowFeatureExtractor(window_sec=1.0)
        features = extractor.extract_flow_features(sample_packet_tcp)
        assert len(features) == 32

    def test_multiple_packets_same_flow(self, sample_packet_tcp):
        """Test flow features accumulate correctly."""
        extractor = FlowFeatureExtractor(window_sec=5.0)
        for _ in range(5):
            features = extractor.extract_flow_features(sample_packet_tcp)
        assert features[0] >= 5.0  # Should have seen 5 packets

    def test_flow_pruning(self):
        """Test that old flows are pruned."""
        import time
        extractor = FlowFeatureExtractor(window_sec=0.1, max_flows=5)
        # Add many different flows
        for i in range(20):
            pkt = {
                "timestamp": time.time(),
                "src_ip": f"10.0.0.{i}",
                "dst_ip": "10.0.0.1",
                "protocol": 6,
                "packet_len": 100,
                "sport": 80,
                "dport": 443,
            }
            extractor.extract_flow_features(pkt)
        # Should have pruned to max_flows
        assert len(extractor._flow_buffers) <= 10  # 2 * max_flows max


class TestNormalizer:
    def test_fit_transform_zscore(self, sample_features):
        """Test Z-score normalization."""
        normalizer = FeatureNormalizer(method="zscore", input_dim=128)
        normalized = normalizer.fit_transform(sample_features)
        assert normalized.shape == sample_features.shape
        assert abs(normalized.mean()) < 0.5  # Should be ~0 mean
        assert abs(normalized.std() - 1.0) < 0.3  # Should be ~1 std

    def test_fit_transform_minmax(self, sample_features):
        """Test MinMax normalization."""
        normalizer = FeatureNormalizer(method="minmax", input_dim=128)
        normalized = normalizer.fit_transform(sample_features)
        assert normalized.min() >= 0.0
        assert normalized.max() <= 1.0

    def test_inverse_transform(self, sample_features):
        """Test inverse transformation."""
        normalizer = FeatureNormalizer(method="zscore", input_dim=128)
        normalized = normalizer.fit_transform(sample_features)
        reconstructed = normalizer.inverse_transform(normalized)
        assert np.allclose(sample_features, reconstructed, atol=1e-5)

    def test_save_load_stats(self, sample_features):
        """Test serialization of normalizer stats."""
        normalizer = FeatureNormalizer(method="zscore", input_dim=128)
        normalizer.fit(sample_features)
        stats = normalizer.save_stats()
        assert stats["fitted"] == True

        new_normalizer = FeatureNormalizer(method="zscore", input_dim=128)
        new_normalizer.load_stats(stats)
        assert new_normalizer._fitted == True

        result = new_normalizer.transform(sample_features)
        original = normalizer.transform(sample_features)
        assert np.allclose(result, original)