"""Tests for packet capture and parsing."""

import pytest
from src.capture.packet_parser import parse_packet, _compute_entropy


class TestPacketParser:
    def test_parse_tcp_packet(self, sample_packet_tcp):
        """Test parsing of a TCP packet."""
        pkt = sample_packet_tcp
        assert pkt["protocol"] == 6
        assert pkt["src_ip"] == "192.168.1.100"
        assert pkt["sport"] == 443
        assert pkt["dport"] == 80
        assert "payload_entropy" in pkt
        assert pkt["payload_entropy"] > 0

    def test_parse_udp_packet(self, sample_packet_udp):
        """Test parsing of a UDP packet."""
        pkt = sample_packet_udp
        assert pkt["protocol"] == 17
        assert pkt["src_ip"] == "192.168.1.200"
        assert pkt["dport"] == 53

    def test_entropy_empty(self):
        """Test entropy of empty payload."""
        entropy = _compute_entropy(b"")
        assert entropy == 0.0

    def test_entropy_constant(self):
        """Test entropy of constant bytes."""
        entropy = _compute_entropy(b"\x00" * 100)
        assert entropy == pytest.approx(0.0, abs=0.01)

    def test_entropy_random(self):
        """Test entropy of random data is > 0."""
        entropy = _compute_entropy(bytes(range(256)))
        assert entropy > 7.0  # Near max for 256 byte values


class TestPacketSniffer:
    def test_sniffer_initialization(self):
        """Test that sniffer can be initialized."""
        from src.capture.sniffer import PacketSniffer
        sniffer = PacketSniffer(interface="lo", bpf_filter="ip")
        assert sniffer.interface == "lo"
        assert sniffer.bpf_filter == "ip"
        assert not sniffer.is_running

    def test_sniffer_stop_when_not_running(self):
        """Test stopping a non-running sniffer."""
        import asyncio
        from src.capture.sniffer import PacketSniffer
        sniffer = PacketSniffer()
        # Should not raise
        asyncio.run(sniffer.stop())