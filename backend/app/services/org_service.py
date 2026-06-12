"""Organisation creation, retrieval, and threshold caching (Section 2.1, Section 8).

F-01 fix: create_organisation() always generates a forwarding slug so every
organisation has a valid scan+<slug>@<domain> inbox address from the moment
it is created.
"""
from __future__ import annotations

import json
import re
import secrets
import uuid
from typing import Any

import redis.asyncio as aioredis
import structlog
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organisation import Organisation

log = structlog.get_logger()

# Must match the TTL used in app/dependencies.py (Section 5.1: Redis SETEX 300)
_THRESHOLD_CACHE_TTL = 300  # seconds


async def create_organisation(db: AsyncSession, name: str) -> Organisation:
    """Create a new Organisation row with a unique forwarding slug.

    Inserts an :class:`~app.models.organisation.Organisation`
    using all Section 3.1 server-side defaults (``suspicious_threshold=30``,
    ``phishing_threshold=80``, ``auto_quarantine_high_risk=true``,
    ``prepend_subject_warning=true``, ``connector_status='unconfigured'``,
    ``data_retention_days=90``).

    The session is flushed (not committed) so that server-generated values
    (``id``, ``created_at``, ``updated_at``) are populated immediately and
    visible to subsequent operations in the same transaction.  The caller's
    ``get_db()`` dependency commits the transaction on success.

    Args:
        db:   Active async database session (from ``get_db()``).
        name: Human-readable organisation name (max 200 chars).

    Returns:
        The newly created and refreshed Organisation ORM instance.
    """
    _base = re.sub(r'[^\w\s-]', '', name.strip().lower())
    _base = re.sub(r'[\s_]+', '-', _base)
    _base = re.sub(r'-+', '-', _base).strip('-')[:50]
    slug = f"{_base}-{secrets.token_hex(2)}" if _base else secrets.token_hex(4)
    org = Organisation(
        name=name,
        forwarding_address_slug=slug,
        # All other columns use the Section 3.1 server-side defaults:
        #   suspicious_threshold = 30
        #   phishing_threshold   = 80
        #   auto_quarantine_high_risk   = true
        #   prepend_subject_warning     = true
        #   connector_status            = 'unconfigured'
        #   data_retention_days         = 90
    )
    db.add(org)
    # flush() writes the INSERT and resolves server defaults without committing
    await db.flush()
    await db.refresh(org)
    log.info(
        "organisation_created",
        org_id=str(org.id),
        name=name,
        slug=slug,
    )
    return org


async def get_org_by_id(db: AsyncSession, org_id: uuid.UUID) -> Organisation:
    """Fetch an Organisation by primary key, raising HTTP 404 if absent.

    Args:
        db:     Active async database session.
        org_id: UUID of the organisation to retrieve.

    Returns:
        The matching Organisation ORM instance.

    Raises:
        :class:`fastapi.HTTPException` with status 404 if no organisation
        exists with the given ``org_id``.
    """
    result = await db.execute(
        select(Organisation).where(Organisation.id == org_id)
    )
    org: Organisation | None = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organisation {org_id} not found",
        )
    return org


async def get_org_thresholds(
    db: AsyncSession,
    redis: aioredis.Redis,
    org_id: uuid.UUID,
) -> dict[str, Any]:
    """Return detection thresholds for an organisation (Redis cache → DB fallback).

    Checks Redis for the key ``org:{org_id}:thresholds`` (TTL 300 s).  On a
    cache hit the JSON payload is deserialised and returned immediately.  On a
    miss the thresholds are read from PostgreSQL, written back to Redis, and
    returned.

    This service-layer version accepts ``(db, redis, org_id)`` explicitly so
    it can be called from Celery tasks that have no FastAPI dependency context.
    The equivalent ``get_org_thresholds()`` FastAPI dependency in
    ``app/dependencies.py`` calls this function internally.

    Args:
        db:     Active async database session (used on cache miss only).
        redis:  Async Redis client.
        org_id: UUID of the organisation whose thresholds are needed.

    Returns:
        A dict with integer keys ``"suspicious_threshold"`` and
        ``"phishing_threshold"``.

    Raises:
        :class:`fastapi.HTTPException` with status 404 if the organisation
        row does not exist in the database.
    """
    cache_key = f"org:{org_id}:thresholds"
    cached = await redis.get(cache_key)
    if cached:
        return json.loads(cached)  # type: ignore[no-any-return]

    result = await db.execute(
        select(
            Organisation.suspicious_threshold,
            Organisation.phishing_threshold,
        ).where(Organisation.id == org_id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organisation {org_id} not found",
        )

    thresholds: dict[str, Any] = {
        "suspicious_threshold": row.suspicious_threshold,
        "phishing_threshold": row.phishing_threshold,
    }
    await redis.setex(cache_key, _THRESHOLD_CACHE_TTL, json.dumps(thresholds))
    return thresholds
