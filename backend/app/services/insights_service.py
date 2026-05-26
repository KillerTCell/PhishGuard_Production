"""Insights computation service (Section 8, FR-04).

compute_insights(org_id, db, redis) -> List[InsightItem]

Insight types (in order):
  1. alert — quarantine spike: this-week quarantine > 2× prev-week quarantine
  2. info  — current detection thresholds (always present)
  3. alert — analysis failures detected: any Email.status == 'failed'

Redis cache: ``SETEX insights:{org_id} 60 <json>``
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import redis.asyncio as aioredis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.email import Email
from app.models.organisation import Organisation
from app.schemas.analysis import InsightItem
from app.schemas.common import InsightType

_INSIGHTS_CACHE_TTL = 60  # seconds


async def compute_insights(
    org_id: uuid.UUID,
    db: AsyncSession,
    redis: aioredis.Redis,
) -> list[InsightItem]:
    """Compute insight cards for the dashboard insights panel.

    Checks Redis cache first (TTL 60 s).  On cache miss, runs 3 DB queries
    and populates the cache before returning.

    Insight types (in order):
      1. alert — quarantine spike (current week > 2× previous week)
      2. info  — current detection thresholds (always present)
      3. alert — analysis failures detected (any email.status == 'failed')

    Args:
        org_id: Organisation UUID (for multi-tenant isolation).
        db:     Async SQLAlchemy session.
        redis:  Async Redis client.

    Returns:
        List of InsightItem instances ready to serialise.
    """
    cache_key = f"insights:{org_id}"
    cached = await redis.get(cache_key)
    if cached:
        return [InsightItem(**item) for item in json.loads(cached)]

    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)
    two_weeks_ago = now - timedelta(days=14)

    # ── 1. Quarantine spike ──────────────────────────────────────────────────
    this_week_q: int = (
        await db.execute(
            select(func.count(Email.id)).where(
                Email.org_id == org_id,
                Email.status == "quarantined",
                Email.received_at >= week_ago,
            )
        )
    ).scalar_one()

    prev_week_q: int = (
        await db.execute(
            select(func.count(Email.id)).where(
                Email.org_id == org_id,
                Email.status == "quarantined",
                Email.received_at >= two_weeks_ago,
                Email.received_at < week_ago,
            )
        )
    ).scalar_one()

    # ── 2. Org thresholds ────────────────────────────────────────────────────
    org = (
        await db.execute(select(Organisation).where(Organisation.id == org_id))
    ).scalar_one()

    # ── 3. Analysis failures ─────────────────────────────────────────────────
    failed_count: int = (
        await db.execute(
            select(func.count(Email.id)).where(
                Email.org_id == org_id,
                Email.status == "failed",
            )
        )
    ).scalar_one()

    # ── Assemble insights ────────────────────────────────────────────────────
    insights: list[InsightItem] = []

    if prev_week_q > 0 and this_week_q > prev_week_q * 2:
        insights.append(
            InsightItem(
                type=InsightType.alert,
                title="Excessive quarantine activity",
                message=(
                    f"This week's quarantine count ({this_week_q}) is more than 2× "
                    f"the previous week ({prev_week_q}). Review your thresholds."
                ),
                severity="high",
            )
        )

    # Threshold info — always present
    insights.append(
        InsightItem(
            type=InsightType.info,
            title="Detection thresholds",
            message=(
                f"Suspicious threshold: {org.suspicious_threshold}. "
                f"Phishing threshold: {org.phishing_threshold}."
            ),
        )
    )

    if failed_count > 0:
        insights.append(
            InsightItem(
                type=InsightType.alert,
                title="Analysis failures detected",
                message="Some emails failed to process. Check the email list for details.",
                severity="medium",
            )
        )

    await redis.setex(
        cache_key,
        _INSIGHTS_CACHE_TTL,
        json.dumps([i.model_dump() for i in insights]),
    )
    return insights
