"""Section 4.12 -- A-10 fix: GET /audit-log

Paginated audit log for admin users.  All rows filtered by org_id.

A-10 fix: Architecture section and UI Figure 18 reference this endpoint
but it was absent from v2 of the API spec.
"""
from __future__ import annotations

import math
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import CurrentUser, get_db, require_admin
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogListItem, AuditLogListResponse

router = APIRouter(tags=["audit"])


@router.get(
    "/audit-log",
    response_model=AuditLogListResponse,
    summary="Paginated audit log (admin only)",
)
async def get_audit_log(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    user_id: Optional[uuid.UUID] = Query(default=None),
    action: Optional[str] = Query(default=None, max_length=100),
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> AuditLogListResponse:
    """Return paginated audit log for the current organisation.

    Supports optional filters:
        user_id -- narrow to a single user's actions
        action  -- partial match on action string

    Ordered by ``created_at DESC``.  Drives UI Figure 18 'Recent admin actions'.
    """
    # Base query — always scoped to org
    base = select(AuditLog).where(AuditLog.org_id == current_user.org_id)

    if user_id is not None:
        base = base.where(AuditLog.user_id == user_id)
    if action is not None:
        base = base.where(AuditLog.action.ilike(f"%{action}%"))

    # Count total
    count_q = select(func.count()).select_from(base.subquery())
    total: int = (await db.execute(count_q)).scalar_one()

    # Fetch page
    offset = (page - 1) * page_size
    rows = (
        await db.execute(
            base.order_by(AuditLog.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
    ).scalars().all()

    # Denormalise user_name — batch fetch user IDs present in the page
    user_ids = {row.user_id for row in rows if row.user_id is not None}
    user_map: dict[uuid.UUID, str] = {}
    if user_ids:
        users = (
            await db.execute(select(User.id, User.full_name).where(User.id.in_(user_ids)))
        ).all()
        user_map = {u.id: u.full_name for u in users}

    items = [
        AuditLogListItem(
            id=row.id,
            user_id=row.user_id,
            user_name=user_map.get(row.user_id) if row.user_id else None,
            action=row.action,
            target_type=row.target_type,
            target_id=row.target_id,
            detail=row.detail,
            ip_address=str(row.ip_address) if row.ip_address else None,
            created_at=row.created_at,
            request_id=row.request_id,
        )
        for row in rows
    ]

    pages = max(1, math.ceil(total / page_size))
    return AuditLogListResponse(items=items, total=total, page=page, pages=pages)
