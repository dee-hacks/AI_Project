"""API router for alerts — REST + WebSocket."""

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query

from src.db.repositories import EventRepository
from src.api.dependencies import get_event_repository, get_event_bus
from src.processor.event_bus import EventBus

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
async def list_alerts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None, regex="^(low|medium|high|critical)$"),
    repo: EventRepository = Depends(get_event_repository),
):
    """List alert events with optional severity filter."""
    events = await repo.get_events(
        limit=limit,
        offset=offset,
        severity=severity,
    )
    return {"alerts": events, "count": len(events)}


@router.get("/alerts/recent")
async def recent_alerts(
    seconds: int = Query(300, ge=10),
    repo: EventRepository = Depends(get_event_repository),
):
    """Get recent alerts from the last N seconds."""
    events = await repo.get_recent_events(seconds=seconds)
    return {"alerts": events, "count": len(events)}


@router.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for real-time alert streaming.
    Subscribes to Redis Pub/Sub 'alerts' channel and forwards to connected clients.
    """
    await websocket.accept()

    event_bus = EventBus()
    try:
        await event_bus.connect()
        pubsub = await event_bus.subscribe("alerts")

        # Keep-alive ping/pong
        async def _ping():
            import asyncio
            while True:
                await asyncio.sleep(30)
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break

        import asyncio
        ping_task = asyncio.create_task(_ping())

        try:
            while True:
                message = await event_bus.get_message(timeout=1.0)
                if message:
                    await websocket.send_json({
                        "type": "alert",
                        "data": message,
                    })

                # Handle incoming control messages
                try:
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                    if data == "ping":
                        await websocket.send_json({"type": "pong"})
                except asyncio.TimeoutError:
                    continue
                except WebSocketDisconnect:
                    break

        finally:
            ping_task.cancel()

    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        await event_bus.close()
        try:
            await websocket.close()
        except Exception:
            pass