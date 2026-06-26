"""Pytest configuration and fixtures."""

import os
import sys
import pytest
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


@pytest.fixture
def sample_packet_tcp():
    """Return a sample TCP packet dict."""
    return {
        "timestamp": 1234567890.123,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "protocol": 6,
        "ttl": 64,
        "packet_len": 520,
        "ip_id": 54321,
        "ip_flags": 2,
        "ip_frag": 0,
        "payload_len": 480,
        "payload_entropy": 4.5,
        "sport": 443,
        "dport": 80,
        "tcp_flags": 24,
        "tcp_window": 65535,
        "tcp_seq": 1000,
        "tcp_ack": 2000,
        "tcp_dataofs": 5,
        "tcp_options": [{"kind": "MSS", "value": 1460}],
        "src_mac": "00:0c:29:ab:cd:ef",
        "dst_mac": "00:50:56:12:34:56",
    }


@pytest.fixture
def sample_packet_udp():
    """Return a sample UDP packet dict."""
    return {
        "timestamp": 1234567890.456,
        "src_ip": "192.168.1.200",
        "dst_ip": "8.8.8.8",
        "protocol": 17,
        "ttl": 128,
        "packet_len": 120,
        "ip_id": 12345,
        "ip_flags": 0,
        "ip_frag": 0,
        "payload_len": 80,
        "payload_entropy": 6.2,
        "sport": 5353,
        "dport": 53,
        "udp_len": 100,
        "src_mac": "b8:27:eb:aa:bb:cc",
        "dst_mac": "00:23:32:11:22:33",
    }


@pytest.fixture
def sample_features():
    """Return a small feature matrix (10 samples, 128 dims)."""
    np.random.seed(42)
    return np.random.randn(10, 128).astype(np.float32)