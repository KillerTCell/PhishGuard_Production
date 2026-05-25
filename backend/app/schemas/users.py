"""Pydantic v2 request/response schemas for routers/users.py.

Covers Section 4.9 (UC admin, UI Figure 17–18):
    GET   /users/stats     — summary counts for the User Management page
    GET   /users           — full list of org members
    GET   /users/{id}      — user detail + last 10 audit actions
    PATCH /users/{id}      — update role or is_active flag (admin only)
    DELETE /users/{id}     — soft-deactivate (admin only)
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from app.schemas.common import UserRole


# ---------------------------------------------------------------------------
# GET /users/stats
# ---------------------------------------------------------------------------


class UserStatsResponse(BaseModel):
    """Summary counts shown on UI Figure 17 cards."""

    total: int
    admins: int
    analysts: int
    active: int


# ---------------------------------------------------------------------------
# Shared user fields
# ---------------------------------------------------------------------------


class UserListItem(BaseModel):
    """Row returned in the user management table."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    full_name: str
    email: str
    role: UserRole
    is_active: bool
    last_active_at: Optional[datetime] = None
    created_at: datetime


# ---------------------------------------------------------------------------
# GET /users/{id}
# ---------------------------------------------------------------------------


class RecentAuditAction(BaseModel):
    """Condensed audit log entry for the user detail sidebar."""

    action: str
    created_at: datetime
    detail: Optional[Any] = None


class UserDetailResponse(BaseModel):
    """User detail with last 10 audit actions (UI Figure 18 'Recent admin actions')."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    full_name: str
    email: str
    role: UserRole
    is_active: bool
    last_active_at: Optional[datetime] = None
    created_at: datetime
    recent_audit_actions: list[RecentAuditAction]


# ---------------------------------------------------------------------------
# PATCH /users/{id}  (Admin only)
# ---------------------------------------------------------------------------


class UserUpdateRequest(BaseModel):
    """Partial update — only role and/or is_active may be changed.

    Router enforces: cannot self-deactivate (403 if id==current_user.id
    AND is_active=False).
    """

    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
