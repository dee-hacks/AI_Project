"""Redis Pub/Sub event bus for real-time alert distribution."""

import json
from typing import Any, Dict, List, Optional, Callable, Awaitable

import redis.asyncio as aioredis


class EventBus:
    """
    Redis Pub/Sub event bus.
    Publishers send alerts to a channel; WebSocket consumers receive them.

    In production, use Redis Sentinel or Cluster for HA.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        channel: str = "alerts",
    ):
        self.host = host
        self.port = port
        self.db = db
        self.channel = channel
        self._redis: Optional[aioredis.Redis] = None
        self._pubsub: Optional[aioredis.client.PubSub] = None

    async def connect(self):
        """Connect to Redis."""
        self._redis = aioredis.Redis(
            host=self.host, port=self.port, db=self.db, decode_responses=True
        )
        self._pubsub = self._redis.pubsub()

    async def publish(self, channel: str, message: Any):
        """Publish a message (dict or list of dicts) to a channel."""
        if self._redis is None:
            await self.connect()

        serialized = json.dumps(message, default=str)
        await self._redis.publish(channel, serialized)

    async def subscribe(self, channel: str) -> aioredis.client.PubSub:
        """Subscribe to a channel and return the PubSub object."""
        if self._pubsub is None:
            await self.connect()
        await self._pubsub.subscribe(channel)
        return self._pubsub

    async def get_message(self, timeout: float = 0.1) -> Optional[Dict[str, Any]]:
        """Get a single message from subscribed channels."""
        if self._pubsub is None:
            return None

        message = await self._pubsub.get_message(
            timeout=timeout, ignore_subscribe_messages=True
        )
        if message is None:
            return None

        try:
            data = json.loads(message["data"])
            return data
        except (json.JSONDecodeError, KeyError):
            return message

    async def close(self):
        """Close connections."""
        if self._pubsub:
            await self._pubsub.unsubscribe()
            await self._pubsub.close()
        if self._redis:
            await self._redis.close()