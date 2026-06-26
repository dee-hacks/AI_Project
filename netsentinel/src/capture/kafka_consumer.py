"""Kafka consumer — alternative packet source for multi-host deployments."""

import json
from typing import AsyncGenerator, Dict, Any, Optional

from aiokafka import AIOKafkaConsumer


class KafkaPacketConsumer:
    """
    Consumes packets from a Kafka topic as an alternative to direct Scapy capture.
    Useful in multi-host setups where one host captures and publishes to Kafka,
    and NetSentinel consumes from Kafka for processing.
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        topic: str = "network-packets",
        group_id: str = "netsentinel-processor",
        auto_offset_reset: str = "latest",
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.auto_offset_reset = auto_offset_reset
        self._consumer: Optional[AIOKafkaConsumer] = None

    async def start(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Connect and yield packets from Kafka topic."""
        self._consumer = AIOKafkaConsumer(
            self.topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            auto_offset_reset=self.auto_offset_reset,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )
        await self._consumer.start()

        try:
            async for msg in self._consumer:
                yield msg.value
        finally:
            await self.stop()

    async def stop(self):
        """Close consumer gracefully."""
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None