"""Repository layer — CRUD operations for MongoDB collections."""

from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

from src.db.mongodb import AsyncMongoClient


class EventRepository:
    """Repository for anomaly events."""

    def __init__(self, db: AsyncMongoClient):
        self.db = db

    async def insert_event(self, event: Dict[str, Any]) -> str:
        """Insert a single anomaly event. Returns the inserted ID."""
        result = await self.db.events.insert_one(event)
        return str(result.inserted_id)

    async def bulk_insert_events(self, events: List[Dict[str, Any]]) -> List[str]:
        """Bulk insert multiple events. Returns list of inserted IDs."""
        if not events:
            return []
        result = await self.db.events.insert_many(events)
        return [str(oid) for oid in result.inserted_ids]

    async def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Get a single event by its MongoDB ObjectId."""
        from bson.objectid import ObjectId
        return await self.db.events.find_one({"_id": ObjectId(event_id)})

    async def get_events(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        src_ip: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        sort_desc: bool = True,
    ) -> List[Dict[str, Any]]:
        """Query events with filtering and pagination."""
        query: Dict[str, Any] = {}

        if severity:
            query["severity"] = severity
        if src_ip:
            query["src_ip"] = src_ip
        if start_time or end_time:
            time_query = {}
            if start_time:
                time_query["$gte"] = start_time
            if end_time:
                time_query["$lte"] = end_time
            query["timestamp"] = time_query

        cursor = self.db.events.find(query)
        cursor = cursor.sort("timestamp", -1 if sort_desc else 1)
        cursor = cursor.skip(offset).limit(limit)

        events = await cursor.to_list(length=limit)
        return events

    async def count_events(self, severity: Optional[str] = None) -> int:
        """Count events, optionally filtered by severity."""
        query = {}
        if severity:
            query["severity"] = severity
        return await self.db.events.count_documents(query)

    async def get_recent_events(self, seconds: int = 300, limit: int = 50) -> List[Dict[str, Any]]:
        """Get events from the last N seconds."""
        cutoff = datetime.utcnow() - timedelta(seconds=seconds)
        query = {"timestamp": {"$gte": cutoff.timestamp()}}
        cursor = self.db.events.find(query).sort("timestamp", -1).limit(limit)
        return await cursor.to_list(length=limit)

    async def acknowledge_event(self, event_id: str) -> bool:
        """Mark an event as acknowledged."""
        from bson.objectid import ObjectId
        result = await self.db.events.update_one(
            {"_id": ObjectId(event_id)},
            {"$set": {"acknowledged": True, "status": "acknowledged"}},
        )
        return result.modified_count > 0


class TopologyRepository:
    """Repository for network topology data."""

    def __init__(self, db: AsyncMongoClient):
        self.db = db

    async def upsert_node(self, node: Dict[str, Any]) -> str:
        """Insert or update a topology node (keyed by IP)."""
        result = await self.db.topology.update_one(
            {"ip": node["ip"]},
            {"$set": node},
            upsert=True,
        )
        return str(result.upserted_id) if result.upserted_id else node["ip"]

    async def get_all_nodes(self) -> List[Dict[str, Any]]:
        """Get all topology nodes."""
        cursor = self.db.topology.find()
        return await cursor.to_list(length=None)

    async def get_node(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get a single node by IP."""
        return await self.db.topology.find_one({"ip": ip})

    async def mark_compromised(self, ip: str, score: float) -> bool:
        """Mark a node as potentially compromised."""
        result = await self.db.topology.update_one(
            {"ip": ip},
            {"$set": {"is_compromised": True, "anomaly_score": score}},
        )
        return result.modified_count > 0

    async def get_compromised_nodes(self) -> List[Dict[str, Any]]:
        """Get all nodes marked as compromised."""
        cursor = self.db.topology.find({"is_compromised": True})
        return await cursor.to_list(length=None)


class ConfigRepository:
    """Repository for application configuration."""

    def __init__(self, db: AsyncMongoClient):
        self.db = db

    async def get_config(self, key: str) -> Optional[Any]:
        """Get a config value by key."""
        doc = await self.db.config.find_one({"key": key})
        return doc["value"] if doc else None

    async def set_config(self, key: str, value: Any) -> bool:
        """Set a config value (upsert)."""
        result = await self.db.config.update_one(
            {"key": key},
            {"$set": {"key": key, "value": value}},
            upsert=True,
        )
        return result.acknowledged

    async def get_all_config(self) -> Dict[str, Any]:
        """Get all configuration as a flat dict."""
        cursor = self.db.config.find()
        docs = await cursor.to_list(length=None)
        return {doc["key"]: doc["value"] for doc in docs}