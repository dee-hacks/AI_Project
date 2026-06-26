"""Detection pipeline — orchestrates capture → feature extraction → AI → store → alert."""

import asyncio
from collections import deque
from typing import Dict, Any, List, Optional

import numpy as np

from src.features.extractor import FeatureExtractor
from src.ai.ensemble import AnomalyEnsemble
from src.processor.event_bus import EventBus
from src.processor.alert_builder import build_alert
from src.db.repositories import EventRepository


class DetectionPipeline:
    """
    Orchestrates the full detection pipeline:
        packet capture → feature extraction → AI inference → storage → alert

    Batches packets for inference efficiency (max BATCH_SIZE or MAX_LATENCY_MS).
    """

    BATCH_SIZE = 256
    MAX_LATENCY_MS = 150
    SLIDING_WINDOW_SEC = 1.0

    def __init__(
        self,
        model: AnomalyEnsemble,
        extractor: FeatureExtractor,
        event_repo: EventRepository,
        event_bus: EventBus,
    ):
        self.model = model
        self.extractor = extractor
        self.event_repo = event_repo
        self.event_bus = event_bus
        self._buffer: deque = deque(maxlen=self.BATCH_SIZE * 2)
        self._last_flush = asyncio.get_event_loop().time()
        self._running = False

    async def process_packet(self, packet: Dict[str, Any]):
        """Process a single packet: buffer and flush when ready."""
        self._buffer.append(packet)
        now = asyncio.get_event_loop().time()
        elapsed_ms = (now - self._last_flush) * 1000

        if len(self._buffer) >= self.BATCH_SIZE or elapsed_ms >= self.MAX_LATENCY_MS:
            await self._flush()

    async def start(self):
        """Start the pipeline."""
        self._running = True

    async def stop(self):
        """Stop the pipeline and flush remaining packets."""
        self._running = False
        if self._buffer:
            await self._flush()

    async def _flush(self):
        """Process current buffer as a batch."""
        batch = list(self._buffer)
        self._buffer.clear()
        self._last_flush = asyncio.get_event_loop().time()

        if not batch:
            return

        try:
            # 1. Feature extraction
            feature_matrix = await self.extractor.transform_batch(batch)

            # 2. AI inference
            is_anomaly, scores = self.model.predict(feature_matrix)

            # 3. Process anomalies
            if is_anomaly.any():
                anomaly_indices = np.where(is_anomaly)[0]
                alerts = []

                for idx in anomaly_indices:
                    pkt = batch[idx]
                    alert = build_alert(
                        packet=pkt,
                        feature_vector=feature_matrix[idx].tolist(),
                        anomaly_score=float(scores[idx]),
                        threshold=float(self.model.threshold),
                        detector="ensemble",
                    )
                    alerts.append(alert)

                # Bulk insert to MongoDB
                if alerts:
                    await self.event_repo.bulk_insert_events(alerts)

                    # Publish to Redis Pub/Sub
                    await self.event_bus.publish("alerts", alerts)

        except Exception as e:
            print(f"Pipeline error during flush: {e}")