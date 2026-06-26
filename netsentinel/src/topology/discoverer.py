"""Network topology discovery via ARP scanning and passive fingerprinting."""

import asyncio
import time
from typing import Dict, Any, List, Optional
from ipaddress import IPv4Network, IPv4Address

from scapy.all import ARP, Ether, IP, srp, conf


class TopologyDiscoverer:
    """
    Discovers network topology using:
    1. Active ARP scanning on configured subnets
    2. Passive observation of source MAC/IP pairs from captured packets
    """

    def __init__(self, networks: List[str] = None, timeout: float = 3.0):
        self.networks = [IPv4Network(net) for net in (networks or ["192.168.1.0/24"])]
        self.timeout = timeout
        self._known_nodes: Dict[str, Dict[str, Any]] = {}

    async def arp_scan(self) -> List[Dict[str, Any]]:
        """
        Perform ARP scan on configured networks.
        Returns list of discovered nodes with IP, MAC, hostname.
        """
        nodes = []
        for network in self.networks:
            discovered = await self._scan_network(str(network))
            nodes.extend(discovered)
        return nodes

    async def _scan_network(self, network: str) -> List[Dict[str, Any]]:
        """Scan a single CIDR network via ARP."""
        loop = asyncio.get_event_loop()

        def _sync_scan():
            """Synchronous ARP scan using Scapy srp."""
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            answered, _ = srp(
                packet,
                timeout=self.timeout,
                verbose=False,
            )

            nodes = []
            for sent, received in answered:
                node = {
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "first_seen": time.time(),
                    "last_seen": time.time(),
                    "is_compromised": False,
                    "anomaly_score": 0.0,
                    "hostname": "",
                    "vendor": self._lookup_vendor(received.hwsrc),
                }
                nodes.append(node)
            return nodes

        nodes = await loop.run_in_executor(None, _sync_scan)
        for node in nodes:
            self._known_nodes[node["ip"]] = node
        return nodes

    def observe_packet(self, packet: Dict[str, Any]):
        """
        Passive observation: update known nodes from packet metadata.
        Call this for every parsed packet to keep topology fresh.
        """
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        src_mac = packet.get("src_mac")
        now = packet.get("timestamp", time.time())

        for ip in [src_ip, dst_ip]:
            if ip and ip not in self._known_nodes:
                self._known_nodes[ip] = {
                    "ip": ip,
                    "mac": src_mac if ip == src_ip else "",
                    "first_seen": now,
                    "last_seen": now,
                    "is_compromised": False,
                    "anomaly_score": 0.0,
                    "hostname": "",
                    "vendor": "",
                }
            elif ip and ip in self._known_nodes:
                self._known_nodes[ip]["last_seen"] = max(
                    self._known_nodes[ip]["last_seen"], now
                )

    def get_all_nodes(self) -> List[Dict[str, Any]]:
        """Return all known topology nodes."""
        return list(self._known_nodes.values())

    def get_node(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get a specific node by IP."""
        return self._known_nodes.get(ip)

    def mark_compromised(self, ip: str, score: float):
        """Mark a node as potentially compromised based on anomaly detection."""
        if ip in self._known_nodes:
            self._known_nodes[ip]["is_compromised"] = True
            self._known_nodes[ip]["anomaly_score"] = max(
                self._known_nodes[ip]["anomaly_score"], score
            )

    def _lookup_vendor(self, mac: str) -> str:
        """
        Look up vendor by MAC OUI.
        Basic implementation — in production, use an OUI database.
        """
        # Common OUI prefixes (simplified)
        vendors = {
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:15:5D": "Microsoft Hyper-V",
            "08:00:27": "Oracle VirtualBox",
            "52:54:00": "QEMU/KVM",
            "00:1A:11": "Google",
            "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi",
            "00:23:32": "Cisco",
            "00:14:22": "Dell",
            "00:04:13": "Juniper",
        }
        prefix = mac.upper()[:8]
        return vendors.get(prefix, "Unknown")

    @property
    def node_count(self) -> int:
        return len(self._known_nodes)