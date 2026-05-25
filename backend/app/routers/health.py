"""Section 4.13 -- N-03 fix: GET /health

Docker HEALTHCHECK, nginx upstream probe, and external monitoring.
Public endpoint -- no auth required, no logging (high-frequency probe).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.dependencies import get_db, get_redis
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    summary="System health check",
    responses={
        200: {"model": HealthResponse},
        503: {"model": HealthResponse, "description": "Dependency unavailable"},
    },
)
async def get_health(
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> JSONResponse:
    """Return system health status.

    Async checks:
        db           -- ``SELECT 1`` against PostgreSQL connection pool
        redis        -- Redis PING
        model_loaded -- ``ml/model.pkl`` exists on disk

    Returns 503 if db or redis is 'error'.  No auth.  No audit log write
    (probes are high-frequency; logging every probe would pollute logs).
    """
    db_status = "ok"
    redis_status = "ok"

    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"

    try:
        await redis.ping()
    except Exception:
        redis_status = "error"

    model_loaded = os.path.isfile("ml/model.pkl")
    overall = "ok" if db_status == "ok" and redis_status == "ok" else "error"

    payload = HealthResponse(
        status=overall,
        db=db_status,
        redis=redis_status,
        model_loaded=model_loaded,
        version=settings.MODEL_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    http_status = (
        status.HTTP_200_OK if overall == "ok" else status.HTTP_503_SERVICE_UNAVAILABLE
    )
    return JSONResponse(status_code=http_status, content=payload.model_dump())
