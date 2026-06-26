"""Feature extractor — orchestrates per-packet and flow-level extraction."""

from typing import Dict, Any, List

import numpy as np

from src.features.per_packet import extract_per_packet_features
from src.features.flow_features import FlowFeatureExtractor
from src.features.normalizer import FeatureNormalizer


class FeatureExtractor:
    """
    Orchestrates extraction of a unified 128-dim feature vector for each packet.
    Combines per-packet (32) + flow-level (32) features, then pads/applies
    transformations to reach the target input_dim.

    Feature vector layout:
      [0:32]   Per-packet features
      [32:64]  Flow-level features
      [64:96]  Derived features (ratios, differences)
      [96:128] Interaction features (pairwise products of key metrics)
    """

    def __init__(
        self,
        input_dim: int = 128,
        window_sec: float = 1.0,
        normalizer: FeatureNormalizer = None,
    ):
        self.input_dim = input_dim
        self.window_sec = window_sec
        self.flow_extractor = FlowFeatureExtractor(window_sec=window_sec)
        self.normalizer = normalizer or FeatureNormalizer(
            method="zscore", input_dim=input_dim
        )

    def extract_single(self, packet: Dict[str, Any]) -> List[float]:
        """
        Extract a full 128-dimensional feature vector from a single packet.
        """
        # Per-packet features (32 dims)
        pp_features = extract_per_packet_features(packet)

        # Flow-level features (32 dims)
        flow_features = self.flow_extractor.extract_flow_features(packet)

        # Derived features (32 dims): packet_rate * avg_size, etc.
        derived = self._compute_derived_features(pp_features, flow_features)

        # Interaction features (32 dims): pairwise products of key metrics
        interactions = self._compute_interaction_features(pp_features, flow_features)

        # Concatenate to 128
        full = pp_features + flow_features + derived + interactions
        return full[: self.input_dim]

    async def transform_batch(self, packets: List[Dict[str, Any]]) -> np.ndarray:
        """
        Transform a batch of packets into a normalized feature matrix.
        Returns np.ndarray of shape (len(packets), input_dim).
        """
        features = []
        for pkt in packets:
            features.append(self.extract_single(pkt))

        matrix = np.array(features, dtype=np.float32)

        if self.normalizer._fitted:
            matrix = self.normalizer.transform(matrix)

        return matrix

    def _compute_derived_features(
        self, pp: List[float], flow: List[float]
    ) -> List[float]:
        """Compute derived feature ratios and combinations (32 dims)."""
        pkt_len = pp[5] * 1500  # denormalize approx
        ttl = pp[6] * 255
        window_size = flow[6] * 1500  # avg pkt size approx
        pkt_rate = flow[4]
        byte_rate = flow[5]

        derived = [
            pkt_rate / max(window_size, 0.01),  # throughput efficiency
            byte_rate / max(pkt_rate, 0.01),  # bytes per packet
            ttl / max(pkt_rate + 1, 0.01),  # TTL per rate
            window_size * pkt_rate,  # bandwidth estimate
            flow[2] * flow[4],  # port entropy * rate
            flow[8] / max(flow[9] + 0.01, 0.01),  # SYN/ACK ratio
            flow[10] * pkt_rate,  # inter-arrival * rate
            flow[11] / max(flow[10] + 0.01, 0.01),  # jitter ratio
            flow[12] / max(pkt_rate + 0.01, 0.01),  # burst ratio
            pp[8] * flow[6],  # payload entropy * avg size
            pp[9] * flow[8],  # flags * SYN ratio
            pp[10] / max(flow[6] + 0.01, 0.01),  # window / avg size
            pp[6] - pp[7],  # TTL - payload_len ratio
            flow[0] * flow[1],  # count * bytes
            flow[3] * pkt_rate,  # duration * rate
            pp[0],  # protocol pass-through
            0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0,
        ]
        return derived[:32]

    def _compute_interaction_features(
        self, pp: List[float], flow: List[float]
    ) -> List[float]:
        """Compute pairwise interaction features (32 dims)."""
        interactions = [
            pp[0] * pp[1],  # protocol * src hash
            pp[0] * pp[2],  # protocol * dst hash
            pp[3] * pp[4],  # sport * dport
            pp[5] * pp[6],  # pkt_len * ttl
            pp[7] * pp[8],  # payload_len * entropy
            pp[9] * pp[10],  # flags * window
            flow[0] * flow[3],  # count * duration
            flow[1] * flow[4],  # bytes * rate
            flow[2] * flow[6],  # port entropy * avg size
            flow[5] * flow[7],  # byte rate * std size
            flow[8] * flow[10],  # SYN ratio * inter-arrival
            flow[9] * flow[11],  # ACK ratio * jitter
            pp[1] * flow[3],  # src hash * duration
            pp[2] * flow[0],  # dst hash * count
            pp[4] * flow[2],  # dport * port entropy
            pp[6] * flow[4],  # ttl * rate
            0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0,
        ]
        return interactions[:32]