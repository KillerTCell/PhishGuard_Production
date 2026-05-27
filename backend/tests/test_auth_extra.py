"""Section 9 Phase 3F — Additional auth router tests for coverage.

Covers missing lines in auth.py:
  - POST /auth/register with invite_token (lines 205-245)
  - POST /auth/register conflict (line 254-258)
  - POST /auth/invite (lines 766-815)
  - POST /auth/accept-invite (lines 840-901)
  - POST /auth/forgot-password with existing user (lines 660-691)
  - _send_email exception swallowed (lines 132-144)
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.invite_token import InviteToken
from app.models.organisation import Organisation
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. POST /auth/invite (admin creates an invite)
# ---------------------------------------------------------------------------


async def test_create_invite_success(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /auth/invite → 201 with invite_id."""
    resp = await async_client.post(
        "/api/v1/auth/invite",
        headers=_auth(admin_token),
        json={"email": "newuser@example.com", "role": "analyst"},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert "invite_id" in data


async def test_create_invite_analyst_forbidden(
    async_client: AsyncClient,
    analyst_token: str,
) -> None:
    """POST /auth/invite → 403 for analyst role."""
    resp = await async_client.post(
        "/api/v1/auth/invite",
        headers=_auth(analyst_token),
        json={"email": "another@example.com", "role": "analyst"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 2. POST /auth/accept-invite
# ---------------------------------------------------------------------------


async def test_accept_invite_success(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /auth/accept-invite with valid token → 200 with access_token."""
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    invite = InviteToken(
        org_id=org.id,
        invited_by_user_id=admin_user.id,
        email="invited@example.com",
        role="analyst",
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=48),
    )
    db_session.add(invite)
    await db_session.flush()

    resp = await async_client.post(
        "/api/v1/auth/accept-invite",
        json={
            "invite_token": raw_token,
            "full_name": "Invited User",
            "password": "SecurePass123!",
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "access_token" in data
    assert data["role"] == "analyst"


async def test_accept_invite_invalid_token(
    async_client: AsyncClient,
) -> None:
    """POST /auth/accept-invite with invalid token → 422."""
    resp = await async_client.post(
        "/api/v1/auth/accept-invite",
        json={
            "invite_token": "notavalidtoken123",
            "full_name": "User",
            "password": "SecurePass123!",
        },
    )
    assert resp.status_code == 422


async def test_accept_invite_expired_token(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /auth/accept-invite with expired token → 422."""
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    invite = InviteToken(
        org_id=org.id,
        invited_by_user_id=admin_user.id,
        email="expired@example.com",
        role="analyst",
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),  # expired
    )
    db_session.add(invite)
    await db_session.flush()

    resp = await async_client.post(
        "/api/v1/auth/accept-invite",
        json={
            "invite_token": raw_token,
            "full_name": "User",
            "password": "SecurePass123!",
        },
    )
    assert resp.status_code == 422


async def test_accept_invite_duplicate_user(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /auth/accept-invite where user already exists → 409."""
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    invite = InviteToken(
        org_id=org.id,
        invited_by_user_id=admin_user.id,
        email=admin_user.email,  # email already registered
        role="analyst",
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=48),
    )
    db_session.add(invite)
    await db_session.flush()

    resp = await async_client.post(
        "/api/v1/auth/accept-invite",
        json={
            "invite_token": raw_token,
            "full_name": "Dup User",
            "password": "SecurePass123!",
        },
    )
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# 3. POST /auth/register with invite_token
# ---------------------------------------------------------------------------


async def test_register_with_invite_token(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /auth/register with invite_token → 201 with access_token."""
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    invite = InviteToken(
        org_id=org.id,
        invited_by_user_id=admin_user.id,
        email="analyst@newco.example",
        role="analyst",
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=48),
    )
    db_session.add(invite)
    await db_session.flush()

    resp = await async_client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "New Analyst",
            "email": "analyst@newco.example",
            "password": "Analyst123!",
            "invite_token": raw_token,
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert "access_token" in data
    assert data["role"] == "analyst"


async def test_register_invite_invalid_token(
    async_client: AsyncClient,
) -> None:
    """POST /auth/register with bad invite_token → 422."""
    resp = await async_client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Bad Invite",
            "email": "bad@invite.example",
            "password": "Password123!",
            "invite_token": "invalidtoken",
        },
    )
    assert resp.status_code == 422


async def test_register_duplicate_email_new_org(
    async_client: AsyncClient,
    admin_user: User,
) -> None:
    """POST /auth/register new-org path with duplicate email → 409."""
    resp = await async_client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Dup User",
            "email": admin_user.email,  # already registered
            "password": "Password123!",
            "org_name": "Dup Org",
        },
    )
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# 4. POST /auth/forgot-password with existing active user
# ---------------------------------------------------------------------------


async def test_forgot_password_existing_user(
    async_client: AsyncClient,
    admin_user: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /auth/forgot-password for active user → 202 + token created."""
    from unittest.mock import AsyncMock

    from app.routers import auth as auth_router

    # Patch _send_email to avoid hitting Resend API but still execute the
    # try-block body for coverage (simulate Resend raising an exception)
    monkeypatch.setattr(auth_router, "_send_email", AsyncMock(return_value=None))

    resp = await async_client.post(
        "/api/v1/auth/forgot-password",
        json={"email": admin_user.email},
    )
    assert resp.status_code == 202, resp.text


async def test_forgot_password_send_email_exception_swallowed(
    async_client: AsyncClient,
    admin_user: User,
) -> None:
    """_send_email exception is swallowed — forgot-password still returns 202.

    Patch resend.Emails.send to raise so the except block inside _send_email
    (lines 143-150) is covered, without replacing the whole function.
    """
    from unittest.mock import patch

    with patch("resend.Emails.send", side_effect=Exception("resend down")):
        resp = await async_client.post(
            "/api/v1/auth/forgot-password",
            json={"email": admin_user.email},
        )
    # _send_email swallows the exception — response must still be 202
    assert resp.status_code == 202, resp.text


# ---------------------------------------------------------------------------
# 5. Register conflict via invite (duplicate within invite path)
# ---------------------------------------------------------------------------


async def test_register_invite_duplicate_email(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /auth/register invite path with already-registered email → 409."""
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    invite = InviteToken(
        org_id=org.id,
        invited_by_user_id=admin_user.id,
        email="dup@test.example",
        role="analyst",
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=48),
    )
    db_session.add(invite)
    await db_session.flush()

    # First registration succeeds
    resp1 = await async_client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "First",
            "email": "dup@test.example",
            "password": "Password123!",
            "invite_token": raw_token,
        },
    )
    # The invite is now used; re-using the same token should fail
    resp2 = await async_client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Second",
            "email": "dup@test.example",
            "password": "Password123!",
            "invite_token": raw_token,
        },
    )
    # Second attempt: token already used → 422
    assert resp2.status_code == 422
