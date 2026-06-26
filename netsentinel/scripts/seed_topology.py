"""
Seed script — generates fake topology data for development and testing.

Usage:
    python scripts/seed_topology.py
    python scripts/seed_topology.py --nodes 50
"""

import argparse
import os
import sys
import random
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.topology.discoverer import TopologyDiscoverer
from src.topology.graph import build_graph


def generate_fake_nodes(count: int = 20) -> list:
    """Generate fake topology nodes for development."""
    vendors = ["Cisco", "Juniper", "Dell", "VMware", "HP", "Ubiquiti", "MikroTik", "Raspberry Pi"]
    node_types = ["router", "switch", "server", "workstation", "printer", "camera", "IoT"]

    nodes = []
    base_ips = ["192.168.1", "10.0.0", "172.16.0"]

    for i in range(count):
        base = random.choice(base_ips)
        ip = f"{base}.{i + 1}"
        node = {
            "ip": ip,
            "mac": ":".join(f"{random.randint(0,255):02x}" for _ in range(6)),
            "hostname": f"{random.choice(node_types)}-{i+1}",
            "first_seen": time.time() - random.randint(0, 86400),
            "last_seen": time.time() - random.randint(0, 3600),
            "is_compromised": random.random() < 0.1,  # 10% compromised
            "anomaly_score": random.random() * 3.0 if random.random() < 0.15 else 0.0,
            "vendor": random.choice(vendors),
        }
        nodes.append(node)

    return nodes


def main():
    parser = argparse.ArgumentParser(description="Seed topology data")
    parser.add_argument("--nodes", type=int, default=20, help="Number of fake nodes")
    parser.add_argument("--output", type=str, default=None, help="Output JSON file")
    args = parser.parse_args()

    print(f"Generating {args.nodes} fake topology nodes...")
    nodes = generate_fake_nodes(args.nodes)
    graph = build_graph(nodes)

    print(f"Nodes: {len(graph['nodes'])}")
    print(f"Links: {len(graph['links'])}")
    compromised = sum(1 for n in nodes if n["is_compromised"])
    print(f"Compromised: {compromised}")

    if args.output:
        import json
        with open(args.output, "w") as f:
            json.dump(graph, f, indent=2)
        print(f"Saved to {args.output}")
    else:
        import json
        print("\nGraph JSON:")
        print(json.dumps(graph, indent=2)[:500] + "...")


if __name__ == "__main__":
    main()