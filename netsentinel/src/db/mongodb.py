"""Async MongoDB connection manager using Motor."""

from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase


class AsyncMongoClient:
    """
    Manages async connection to MongoDB via Motor.
    Provides database access with automatic connection pooling.
    """

    def __init__(
        self,
        uri: str = "mongodb://localhost:27017",
        database: str = "netsentinel",
        max_pool_size: int = 100,
        min_pool_size: int = 10,
    ):
        self.uri = uri
        self.database_name = database
        self.max_pool_size = max_pool_size
        self.min_pool_size = min_pool_size
        self._client: Optional[AsyncIOMotorClient] = None
        self._db: Optional[AsyncIOMotorDatabase] = None

    async def connect(self):
        """Establish connection to MongoDB."""
        self._client = AsyncIOMotorClient(
            self.uri,
            maxPoolSize=self.max_pool_size,
            minPoolSize=self.min_pool_size,
        )
        self._db = self._client[self.database_name]

        # Verify connection
        await self._client.admin.command("ping")
        print(f"Connected to MongoDB: {self.uri}")

    async def close(self):
        """Close the MongoDB connection."""
        if self._client:
            self._client.close()
            self._client = None
            self._db = None

    @property
    def db(self) -> AsyncIOMotorDatabase:
        """Get the database instance."""
        if self._db is None:
            raise RuntimeError("Not connected to MongoDB. Call connect() first.")
        return self._db

    @property
    def is_connected(self) -> bool:
        return self._client is not None

    # Convenience accessors for collections
    @property
    def events(self):
        return self.db["anomaly_events"]

    @property
    def topology(self):
        return self.db["network_topology"]

    @property
    def config(self):
        return self.db["app_config"]

    async def create_indexes(self):
        """Create recommended indexes for performance."""
        await self.events.create_index("timestamp", background=True)
        await self.events.create_index("severity", background=True)
        await self.events.create_index([("src_ip", 1), ("timestamp", -1)], background=True)
        await self.events.create_index("alert_id", unique=True, background=True)

        await self.topology.create_index("ip", unique=True, background=True)
        await self.topology.create_index("last_seen", background=True)