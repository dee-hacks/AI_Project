"""
Benchmark script — measures throughput and latency of the detection pipeline.

Usage:
    python scripts/benchmark.py --num-packets 10000
    python scripts/benchmark.py --num-packets 50000 --batch-size 512
"""

import argparse
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.features.extractor import FeatureExtractor


def generate_benchmark_packets(n: int) -> list:
    """Generate synthetic packets for benchmarking."""
    packets = []
    for i in range(n):
        packet = {
            "timestamp": time.time() + i * 0.001,
            "src_ip": f"192.168.1.{i % 255}",
            "dst_ip": f"10.0.0.{(i // 255) % 255}",
            "protocol": 6 if i % 4 != 0 else 17,
            "ttl": 64 + (i % 64),
            "packet_len": 40 + (i % 1460),
            "sport": 80 + (i % 100),
            "dport": 443 + (i % 100),
            "tcp_flags": i % 32,
            "tcp_window": 65535,
            "payload_len": i % 1000,
            "payload_entropy": 4.0 + np.random.random() * 2.0,
        }
        packets.append(packet)
    return packets


def main():
    parser = argparse.ArgumentParser(description="Benchmark detection pipeline")
    parser.add_argument("--num-packets", type=int, default=10000, help="Number of packets")
    parser.add_argument("--batch-size", type=int, default=256, help="Batch size")
    args = parser.parse_args()

    print(f"Generating {args.num_packets} benchmark packets...")
    packets = generate_benchmark_packets(args.num_packets)

    extractor = FeatureExtractor()

    # Warmup
    print("Warming up...")
    for pkt in packets[:100]:
        extractor.extract_single(pkt)

    # Benchmark feature extraction
    print(f"Benchmarking feature extraction (batch size={args.batch_size})...")
    start = time.time()
    for i in range(0, len(packets), args.batch_size):
        batch = packets[i : i + args.batch_size]
        features = []
        for pkt in batch:
            features.append(extractor.extract_single(pkt))
    elapsed = time.time() - start

    total = len(packets)
    throughput = total / elapsed if elapsed > 0 else 0
    latency_ms = (elapsed / total) * 1000 if total > 0 else 0

    print(f"\nResults:")
    print(f"  Total packets: {total}")
    print(f"  Time: {elapsed:.3f}s")
    print(f"  Throughput: {throughput:.0f} packets/sec")
    print(f"  Avg latency per packet: {latency_ms:.3f}ms")
    print(f"  Feature dim: {extractor.input_dim}")

    # Memory estimate
    feature_size = extractor.input_dim * 4  # float32
    print(f"  Feature vector size: {feature_size} bytes")
    print(f"  Memory for {total} vectors: {feature_size * total / 1024 / 1024:.2f} MB")


if __name__ == "__main__":
    main()