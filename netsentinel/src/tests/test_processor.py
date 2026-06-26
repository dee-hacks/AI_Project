"""Tests for the processor pipeline."""

import pytest
from src.processor.alert_builder import build_alert


class TestAlertBuilder:
    def test_build_alert(self, sample_packet_tcp):
        """Test alert building from a packet."""
        alert = build_alert(
            packet=sample_packet_tcp,
            feature_vector=[0.1] * 128,
            anomaly_score=2.5,
            threshold=1.0,
            detector="ensemble",
        )
        assert alert["severity"] == "high"
        assert alert["src_ip"] == "192.168.1.100"
        assert alert["detector"] == "ensemble"
        assert alert["anomaly_score"] == 2.5
        assert alert["status"] == "open"
        assert not alert["acknowledged"]

    def test_build_alert_critical(self, sample_packet_udp):
        """Test alert with critical score."""
        alert = build_alert(
            packet=sample_packet_udp,
            feature_vector=[0.5] * 128,
            anomaly_score=5.0,
            threshold=1.0,
            detector="ensemble",
        )
        assert alert["severity"] == "critical"

    def test_build_alert_low(self, sample_packet_tcp):
        """Test alert with low score."""
        alert = build_alert(
            packet=sample_packet_tcp,
            feature_vector=[0.1] * 128,
            anomaly_score=0.6,
            threshold=1.0,
            detector="ensemble",
        )
        assert alert["severity"] == "low"

    def test_build_alert_medium(self, sample_packet_tcp):
        """Test alert with medium score."""
        alert = build_alert(
            packet=sample_packet_tcp,
            feature_vector=[0.1] * 128,
            anomaly_score=1.5,
            threshold=1.0,
            detector="ensemble",
        )
        assert alert["severity"] == "medium"


class TestPipeline:
    def test_pipeline_initialization(self):
        """Test pipeline can be initialized."""
        from src.processor.pipeline import DetectionPipeline
        # Just test import and basic structure
        assert DetectionPipeline.BATCH_SIZE == 256
        assert DetectionPipeline.MAX_LATENCY_MS == 150