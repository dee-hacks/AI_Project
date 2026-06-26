"""API router for application configuration."""

from fastapi import APIRouter, Depends, HTTPException

from src.db.repositories import ConfigRepository
from src.api.dependencies import get_config_repository

router = APIRouter(tags=["config"])


@router.get("/config")
async def get_all_config(
    repo: ConfigRepository = Depends(get_config_repository),
):
    """Get all configuration values."""
    config = await repo.get_all_config()
    return config


@router.get("/config/{key}")
async def get_config(
    key: str,
    repo: ConfigRepository = Depends(get_config_repository),
):
    """Get a specific configuration value by key."""
    value = await repo.get_config(key)
    if value is None:
        raise HTTPException(status_code=404, detail="Config key not found")
    return {key: value}


@router.put("/config/{key}")
async def set_config(
    key: str,
    value: dict,
    repo: ConfigRepository = Depends(get_config_repository),
):
    """Set a configuration value (upsert)."""
    if "value" not in value:
        raise HTTPException(status_code=400, detail="Body must contain 'value' key")
    success = await repo.set_config(key, value["value"])
    return {"status": "updated" if success else "failed", "key": key}