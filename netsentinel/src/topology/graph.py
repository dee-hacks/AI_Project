"""NetworkX graph builder — converts discovered topology to D3.js JSON format."""

from typing import Dict, Any, List

import networkx as nx


def build_graph(nodes: List[Dict[str, Any]]) -> dict:
    """
    Build a NetworkX graph from topology nodes and convert to D3.js format.

    Args:
        nodes: List of node dicts from TopologyDiscoverer

    Returns:
        Dict with 'nodes' and 'links' arrays for D3 force-directed graph
    """
    G = nx.Graph()

    for node in nodes:
        G.add_node(
            node["ip"],
            id=node["ip"],
            ip=node["ip"],
            mac=node.get("mac", ""),
            hostname=node.get("hostname", ""),
            is_compromised=node.get("is_compromised", False),
            anomaly_score=node.get("anomaly_score", 0.0),
            first_seen=node.get("first_seen", 0),
            last_seen=node.get("last_seen", 0),
            vendor=node.get("vendor", ""),
        )

    # Infer links from /24 subnet membership (same /24 = connected to gateway)
    # In production, actual link data would come from LLDP/CDP/SNMP
    _infer_subnet_links(G, nodes)

    # Convert to D3 JSON format
    d3_data = _to_d3_json(G)
    return d3_data


def _infer_subnet_links(G: nx.Graph, nodes: List[Dict[str, Any]]):
    """Infer network links based on subnet membership."""
    subnets: Dict[str, List[str]] = {}

    for node in nodes:
        ip = node.get("ip", "0.0.0.0")
        parts = ip.split(".")
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            if subnet not in subnets:
                subnets[subnet] = []
            subnets[subnet].append(ip)

    # Add edges between nodes in the same subnet (connect to a virtual gateway)
    for subnet, members in subnets.items():
        if len(members) > 1:
            for i in range(1, len(members)):
                G.add_edge(
                    members[0],
                    members[i],
                    protocol="ethernet",
                    last_active=max(
                        G.nodes[members[0]].get("last_seen", 0),
                        G.nodes[members[i]].get("last_seen", 0),
                    ),
                    is_anomalous=False,
                )


def _to_d3_json(G: nx.Graph) -> dict:
    """Convert NetworkX graph to D3.js force-directed layout JSON."""
    nodes = []
    for node_id, data in G.nodes(data=True):
        node = {"id": node_id}
        node.update({k: v for k, v in data.items() if k != "id"})
        nodes.append(node)

    links = []
    for u, v, data in G.edges(data=True):
        link = {
            "source": u,
            "target": v,
            "protocol": data.get("protocol", "unknown"),
            "last_active": data.get("last_active", 0),
            "is_anomalous": data.get("is_anomalous", False),
        }
        links.append(link)

    return {"nodes": nodes, "links": links}