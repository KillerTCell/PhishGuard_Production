"""Pydantic v2 request/response schemas for routers/auth.py.

Covers Section 4.1 (FR-01, UC-01):
    POST /auth/register
    POST /auth/login
    GET  /auth/me
    POST /auth/refresh
    POST /auth/logout          (204 — no body)
    POST /auth/forgot-password
    POST /auth/reset-password
    POST /auth/invite
    POST /auth/accept-invite
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator

from app.schemas.common import UserRole as UserRole  # explicit re-export for mypy --strict


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    """Registration body.

    A-08 fix: 422 if *neither* org_name nor invite_token is provided.
    The validator is declared here; the router also re-validates at the
    business-logic level so the error message stays user-friendly.
    """

    full_name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    org_name: Optional[str] = Field(default=None, max_length=120)
    invite_token: Optional[str] = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def require_org_or_invite(self) -> "RegisterRequest":
        """Ensure at least one of org_name or invite_token is supplied."""
        if not self.org_name and not self.invite_token:
            raise ValueError(
                "Organisation name required — provide org_name for a new organisation "
                "or invite_token to join an existing one."
            )
        return self


class RegisterResponse(BaseModel):
    """Response after successful registration."""

    model_config = ConfigDict(from_attributes=True)

    access_token: str
    refresh_token: str
    role: UserRole
    org_id: uuid.UUID
    forwarding_address: str


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """Login credentials."""

    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    """Successful login response.

    refresh_token is set as an HttpOnly Secure SameSite=Strict cookie (7d)
    by the router — it is NOT included in this JSON body (NFR-2).
    """

    model_config = ConfigDict(from_attributes=True)

    access_token: str
    role: UserRole
    org_id: uuid.UUID
    org_name: str
    unread_count: int


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------


class MeResponse(BaseModel):
    """Current-user profile returned on app load."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    full_name: str
    email: str
    role: UserRole
    org_id: uuid.UUID
    org_name: str
    is_active: bool
    last_active_at: Optional[datetime] = None
    unread_count: int
    forwarding_address: str


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------


class RefreshResponse(BaseModel):
    """New access token issued after refresh-cookie rotation."""

    access_token: str


# ---------------------------------------------------------------------------
# POST /auth/forgot-password
# ---------------------------------------------------------------------------


class ForgotPasswordRequest(BaseModel):
    """Initiates the password-reset email flow.

    Always returns 202 to prevent user-enumeration (UC-01 edge flow).
    """

    email: EmailStr


# ---------------------------------------------------------------------------
# POST /auth/reset-password
# ---------------------------------------------------------------------------


class ResetPasswordRequest(BaseModel):
    """Consume a signed reset link and set a new password."""

    token: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=8, max_length=128)


# ---------------------------------------------------------------------------
# POST /auth/invite   (Admin only)
# ---------------------------------------------------------------------------


class InviteRequest(BaseModel):
    """Invite a new team member to the organisation."""

    email: EmailStr
    role: UserRole


class InviteResponse(BaseModel):
    """Confirmation that the invite was created and email dispatched."""

    invite_id: uuid.UUID


# ---------------------------------------------------------------------------
# POST /auth/accept-invite   (Public — signed token)
# ---------------------------------------------------------------------------


class AcceptInviteRequest(BaseModel):
    """Accept an emailed invite and create an account."""

    invite_token: str = Field(min_length=1, max_length=512)
    full_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=8, max_length=128)


class AcceptInviteResponse(BaseModel):
    """Session tokens issued immediately after accepting an invite."""

    access_token: str
    role: UserRole
    org_id: uuid.UUID
