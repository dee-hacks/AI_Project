"""Packet parser: raw bytes / Scapy packets → structured dictionary."""

from typing import Any, Dict, Optional
from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw


def parse_packet(packet: Any) -> Optional[Dict[str, Any]]:
    """
    Extract structured fields from a Scapy packet.
    Returns None for non-IP packets (ARP, IPv6, etc.).
    """
    if IP not in packet:
        return None

    ip_layer = packet[IP]
    parsed: Dict[str, Any] = {
        "timestamp": packet.time,
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": ip_layer.proto,  # 6=TCP, 17=UDP, 1=ICMP
        "ttl": ip_layer.ttl,
        "packet_len": len(packet),
        "ip_id": ip_layer.id,
        "ip_flags": ip_layer.flags,
        "ip_frag": ip_layer.frag,
    }

    # Payload entropy
    if Raw in packet:
        payload = bytes(packet[Raw])
        parsed["payload_len"] = len(payload)
        parsed["payload_entropy"] = _compute_entropy(payload)
    else:
        parsed["payload_len"] = 0
        parsed["payload_entropy"] = 0.0

    # TCP-specific fields
    if TCP in packet:
        tcp = packet[TCP]
        parsed.update({
            "sport": tcp.sport,
            "dport": tcp.dport,
            "tcp_flags": int(tcp.flags),
            "tcp_window": tcp.window,
            "tcp_seq": tcp.seq,
            "tcp_ack": tcp.ack,
            "tcp_dataofs": tcp.dataofs,
            "tcp_options": _extract_tcp_options(tcp),
        })
    elif UDP in packet:
        udp = packet[UDP]
        parsed.update({
            "sport": udp.sport,
            "dport": udp.dport,
            "udp_len": udp.len,
        })
    elif ICMP in packet:
        icmp = packet[ICMP]
        parsed.update({
            "icmp_type": icmp.type,
            "icmp_code": icmp.code,
        })

    # Ethernet
    if Ether in packet:
        parsed["src_mac"] = packet[Ether].src
        parsed["dst_mac"] = packet[Ether].dst

    return parsed


def _compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of byte payload."""
    if not data:
        return 0.0
    from math import log2
    entropy = 0.0
    length = len(data)
    for byte_val in range(256):
        count = data.count(byte_val)
        if count > 0:
            p = count / length
            entropy -= p * log2(p)
    return entropy


def _extract_tcp_options(tcp_layer: Any) -> list:
    """Extract TCP options as a list of (kind, value) tuples."""
    options = []
    try:
        for opt in tcp_layer.options:
            if isinstance(opt, tuple) and len(opt) >= 1:
                options.append({"kind": opt[0], "value": opt[1] if len(opt) > 1 else None})
    except Exception:
        pass
    return options