"""API dependencies — session, event bus, and model injection."""

from typing import Optional

from src.db.mongodb import AsyncMongoClient
from src.db.repositories import EventRepository, TopologyRepository, ConfigRepository
from src.processor.event_bus import EventBus
from src.ai.ensemble import AnomalyEnsemble

# Global instance holders
_db: Optional[AsyncMongoClient] = None
_event_bus: Optional[EventBus] = None
_model: Optional[AnomalyEnsemble] = None


def get_db() -> AsyncMongoClient:
    """Get the MongoDB client singleton."""
    global _db
    if _db is None:
        _db = AsyncMongoClient()
    return _db


def get_event_bus() -> EventBus:
    """Get the Redis EventBus singleton."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


def get_model() -> AnomalyEnsemble:
    """Get the AI ensemble model singleton."""
    global _model
    if _model is None:
        _model = AnomalyEnsemble()
    return _model


def get_event_repository() -> EventRepository:
    """Get EventRepository (depends on db)."""
    return EventRepository(get_db())


def get_topology_repository() -> TopologyRepository:
    """Get TopologyRepository (depends on db)."""
    return TopologyRepository(get_db())


def get_config_repository() -> ConfigRepository:
    """Get ConfigRepository (depends on db)."""
    return ConfigRepository(get_db())