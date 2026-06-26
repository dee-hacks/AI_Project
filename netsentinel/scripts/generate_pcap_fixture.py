"""
Generate sample .pcap files for testing and development.
Creates a mix of normal and anomalous traffic patterns.

Usage:
    python scripts/generate_pcap_fixture.py
    python scripts/generate_pcap_fixture.py --output data/benchmarks/sample.pcap --num-packets 500
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import (
    Ether, IP, TCP, UDP, ICMP,
    Raw, wrpcap
)
from scapy.contrib.modbus import ModbusADURequest


def generate_pcap(output_path: str, num_packets: int = 200):
    """
    Generate a .pcap file with a mix of normal and anomalous traffic.

    Normal traffic:
    - HTTP/HTTPS (TCP 80, 443)
    - DNS queries (UDP 53)
    - ICMP pings

    Anomalous traffic:
    - Port scan patterns (SYN to sequential ports)
    - Large payloads
    - Unusual TTL values
    - High entropy payloads
    """
    packets = []
    base_time = time.time()

    # Normal HTTP traffic
    for i in range(num_packets // 3):
        pkt = (
            Ether(src="00:0c:29:ab:cd:ef", dst="00:50:56:12:34:56")
            / IP(src="192.168.1.100", dst="10.0.0.1", ttl=64)
            / TCP(sport=45000 + i, dport=80, flags="A", window=65535)
            / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
        pkt.time = base_time + i * 0.01
        packets.append(pkt)

    # Normal DNS traffic
    for i in range(num_packets // 4):
        pkt = (
            Ether(src="b8:27:eb:aa:bb:cc", dst="00:23:32:11:22:33")
            / IP(src="192.168.1.200", dst="8.8.8.8", ttl=128)
            / UDP(sport=5353, dport=53)
            / Raw(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                  b"\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00"
                  b"\x00\x01\x00\x01")
        )
        pkt.time = base_time + i * 0.05
        packets.append(pkt)

    # Normal ICMP
    for i in range(num_packets // 6):
        pkt = (
            Ether(src="00:50:56:ab:cd:01", dst="00:0c:29:12:34:56")
            / IP(src="10.0.0.2", dst="192.168.1.1", ttl=64)
            / ICMP(type=8, code=0)
            / Raw(b"\x00" * 56)
        )
        pkt.time = base_time + i * 0.5
        packets.append(pkt)

    # Anomalous: Port scan (SYN to sequential ports)
    for i in range(num_packets // 6):
        pkt = (
            Ether(src="00:1a:11:de:ad:be", dst="00:50:56:12:34:56")
            / IP(src="10.10.10.10", dst="192.168.1.100", ttl=32)  # Unusual TTL
            / TCP(sport=31337, dport=10000 + i, flags="S", window=1024)  # SYN scan
        )
        pkt.time = base_time + i * 0.001  # Fast succession
        packets.append(pkt)

    # Anomalous: Large data exfiltration
    for i in range(num_packets // 12):
        large_payload = b"\x00" * 100 + b"\xff" * 400  # Low entropy large payload
        pkt = (
            Ether(src="00:04:13:ca:fe:ba", dst="00:50:56:12:34:56")
            / IP(src="192.168.1.50", dst="45.33.32.156", ttl=255)
            / TCP(sport=443, dport=9999, flags="PA", window=65535)
            / Raw(large_payload)
        )
        pkt.time = base_time + i * 0.1
        packets.append(pkt)

    # Anomalous: ICMP flood
    for i in range(num_packets // 12):
        pkt = (
            Ether(src="de:ad:be:ef:00:01", dst="ff:ff:ff:ff:ff:ff")
            / IP(src="203.0.113.1", dst="192.168.1.255", ttl=128)
            / ICMP(type=8, code=0)
            / Raw(b"\x00" * 1400)
        )
        pkt.time = base_time + i * 0.0005  # Burst
        packets.append(pkt)

    # Shuffle for realism
    import random
    random.shuffle(packets)

    # Sort by timestamp
    packets.sort(key=lambda p: p.time)

    # Write to file
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    wrpcap(output_path, packets)
    print(f"Generated {len(packets)} packets → {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate .pcap test fixture")
    parser.add_argument(
        "--output", type=str, default="src/tests/fixtures/sample_packets.pcap",
        help="Output .pcap file path"
    )
    parser.add_argument(
        "--num-packets", type=int, default=200,
        help="Number of packets to generate"
    )
    args = parser.parse_args()

    generate_pcap(args.output, args.num_packets)


if __name__ == "__main__":
    main()