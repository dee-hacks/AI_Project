"""API router for anomaly events."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from src.db.repositories import EventRepository
from src.api.dependencies import get_event_repository

router = APIRouter(tags=["events"])


@router.get("/events")
async def list_events(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None, regex="^(low|medium|high|critical)$"),
    src_ip: Optional[str] = None,
    repo: EventRepository = Depends(get_event_repository),
):
    """List anomaly events with optional filtering."""
    events = await repo.get_events(
        limit=limit,
        offset=offset,
        severity=severity,
        src_ip=src_ip,
    )
    return {"events": events, "count": len(events)}


@router.get("/events/{event_id}")
async def get_event(
    event_id: str,
    repo: EventRepository = Depends(get_event_repository),
):
    """Get a single event by ID."""
    event = await repo.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get("/events/stats/summary")
async def events_summary(
    repo: EventRepository = Depends(get_event_repository),
):
    """Get summary statistics for events."""
    total = await repo.count_events()
    high = await repo.count_events(severity="high")
    critical = await repo.count_events(severity="critical")
    return {
        "total": total,
        "high": high,
        "critical": critical,
        "recent_5min": len(await repo.get_recent_events(seconds=300)),
    }


@router.post("/events/{event_id}/acknowledge")
async def acknowledge_event(
    event_id: str,
    repo: EventRepository = Depends(get_event_repository),
):
    """Acknowledge an anomaly event."""
    success = await repo.acknowledge_event(event_id)
    if not success:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"status": "acknowledged", "event_id": event_id}