"""FastAPI application factory for NetSentinel."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routers import events, topology, alerts, config
from src.api.dependencies import get_db, get_event_bus, get_model
from src.db.mongodb import AsyncMongoClient


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan: initialize and cleanup resources."""
    # Startup
    db = AsyncMongoClient()
    await db.connect()
    await db.create_indexes()

    # Inject into app state
    app.state.db = db
    app.state.event_bus = get_event_bus()
    app.state.model = get_model()

    yield

    # Shutdown
    await db.close()
    if hasattr(app.state, "event_bus") and app.state.event_bus:
        await app.state.event_bus.close()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="NetSentinel API",
        description="AI-Powered Network Anomaly Detection",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    app.include_router(events.router, prefix="/api/v1")
    app.include_router(topology.router, prefix="/api/v1")
    app.include_router(alerts.router, prefix="/api/v1")
    app.include_router(config.router, prefix="/api/v1")

    # Health check
    @app.get("/health")
    async def health_check():
        return {"status": "ok"}

    return app