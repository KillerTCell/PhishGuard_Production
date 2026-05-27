"""Section 9 Phase 1H — Authentication endpoint tests (13 tests).

All tests use the async_client fixture which wires the FastAPI app to an
in-transaction PostgreSQL session (rolled back after each test) and a
fresh FakeRedis instance.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.invite_token import InviteToken
from app.models.organisation import Organisation
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

_HEADERS_JSON = {"Content-Type": "application/json"}
_TEST_PASSWORD = "test-password-123"
_NEW_PASSWORD = "new-password-456"


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. test_register_first_user_creates_org
# ---------------------------------------------------------------------------


async def test_register_first_user_creates_org(async_client: AsyncClient) -> None:
    """POST /auth/register with org_name → 201, role=admin, forwarding address."""
    resp = await async_client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Alice Admin",
            "email": f"alice_{uuid.uuid4().hex[:6]}@example.com",
            "password": _TEST_PASSWORD,
            "org_name": "Alice's Bakery",
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["role"] == "admin"
    assert "access_token" in data
    assert "forwarding_address" in data
    assert "scan+" in data["forwarding_address"]
    assert "@" in data["forwarding_address"]
    assert uuid.UUID(data["org_id"])   # valid UUID


# ---------------------------------------------------------------------------
# 2. test_register_missing_both
# ---------------------------------------------------------------------------


async def test_register_missing_both(async_client: AsyncClient) -> None:
    """POST /auth/register with neither org_name nor invite_token → 422 (A-08)."""
    resp = await async_client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Bob",
            "email": "bob@example.com",
            "password": _TEST_PASSWORD,
        },
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 3. test_login_success
# ---------------------------------------------------------------------------


async def test_login_success(async_client: AsyncClient, admin_user: User) -> None:
    """POST /auth/login with correct credentials → 200 + access_token."""
    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": _TEST_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "access_token" in data
    assert data["role"] == "admin"
    assert str(admin_user.org_id) == data["org_id"]
    # Refresh cookie must be set
    assert "refresh_token" in async_client.cookies


# ---------------------------------------------------------------------------
# 4. test_login_wrong_password
# ---------------------------------------------------------------------------


async def test_login_wrong_password(async_client: AsyncClient, admin_user: User) -> None:
    """POST /auth/login with wrong password → 401."""
    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": "totally-wrong"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 5. test_login_inactive_user
# ---------------------------------------------------------------------------


async def test_login_inactive_user(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org: Organisation,
) -> None:
    """POST /auth/login for a deactivated account → 403."""
    from app.core.security import hash_password
    from tests.conftest import UserFactory

    inactive = UserFactory(
        org_id=org.id,
        is_active=False,
        password_hash=hash_password(_TEST_PASSWORD),
    )
    db_session.add(inactive)
    await db_session.flush()

    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": inactive.email, "password": _TEST_PASSWORD},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 6. test_login_rate_limit
# ---------------------------------------------------------------------------


async def test_login_rate_limit(async_client: AsyncClient, admin_user: User) -> None:
    """Four failed logins → 5th attempt returns 429 + Retry-After (>= threshold)."""
    payload = {"email": admin_user.email, "password": "wrong-password"}

    # Attempts 1-4: counter < _LOGIN_MAX_ATTEMPTS (5) → password check → 401
    for attempt in range(1, 5):
        r = await async_client.post("/api/v1/auth/login", json=payload)
        assert r.status_code == 401, f"Attempt {attempt} should be 401, got {r.status_code}"

    # 5th attempt — INCR brings counter to 5 (>= _LOGIN_MAX_ATTEMPTS) → 429
    r = await async_client.post("/api/v1/auth/login", json=payload)
    assert r.status_code == 429, r.text
    assert "Retry-After" in r.headers


# ---------------------------------------------------------------------------
# 7. test_auth_me
# ---------------------------------------------------------------------------


async def test_auth_me(
    async_client: AsyncClient,
    admin_token: str,
    admin_user: User,
    org: Organisation,
) -> None:
    """GET /auth/me with valid Bearer token → 200 + full profile."""
    resp = await async_client.get("/api/v1/auth/me", headers=_auth_header(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["email"] == admin_user.email
    assert data["role"] == "admin"
    assert data["org_name"] == org.name
    assert "forwarding_address" in data
    assert "scan+" in data["forwarding_address"]


# ---------------------------------------------------------------------------
# 8. test_refresh_token
# ---------------------------------------------------------------------------


async def test_refresh_token(async_client: AsyncClient, admin_user: User) -> None:
    """POST /auth/refresh with valid refresh cookie → 200 + new access_token."""
    # Login to set the refresh cookie
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": _TEST_PASSWORD},
    )
    assert login.status_code == 200
    assert "refresh_token" in async_client.cookies

    # Refresh
    refresh = await async_client.post("/api/v1/auth/refresh")
    assert refresh.status_code == 200, refresh.text
    data = refresh.json()
    assert "access_token" in data
    # Cookie should be rotated (still present)
    assert "refresh_token" in async_client.cookies


# ---------------------------------------------------------------------------
# 9. test_logout_blacklists_token
# ---------------------------------------------------------------------------


async def test_logout_blacklists_token(
    async_client: AsyncClient,
    admin_user: User,
) -> None:
    """Logout blacklists the refresh token; subsequent /auth/refresh → 401."""
    # Login
    login = await async_client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": _TEST_PASSWORD},
    )
    assert login.status_code == 200

    # Logout — blacklists the refresh JTI and clears the cookie
    logout = await async_client.post(
        "/api/v1/auth/logout",
        headers=_auth_header(login.json()["access_token"]),
    )
    assert logout.status_code == 204

    # The refresh cookie is now gone; trying to refresh → 401
    refresh = await async_client.post("/api/v1/auth/refresh")
    assert refresh.status_code == 401


# ---------------------------------------------------------------------------
# 10. test_rbac_analyst_blocked
# ---------------------------------------------------------------------------


async def test_rbac_analyst_blocked(
    async_client: AsyncClient,
    analyst_token: str,
) -> None:
    """Analyst token → 403 on all admin-only endpoints (Section 7.2 RBAC)."""
    fake_id = "00000000-0000-0000-0000-000000000001"
    headers = _auth_header(analyst_token)

    admin_endpoints: list[tuple[str, str, dict | None]] = [
        ("POST", "/api/v1/auth/invite", {"email": "x@x.com", "role": "analyst"}),
        ("GET", "/api/v1/users", None),
        ("GET", "/api/v1/users/stats", None),
        ("PATCH", f"/api/v1/users/{fake_id}", {"is_active": False}),
        ("DELETE", f"/api/v1/users/{fake_id}", None),
        ("DELETE", f"/api/v1/emails/{fake_id}", None),
        ("GET", "/api/v1/audit-log", None),
        ("POST", "/api/v1/settings/export", None),
    ]

    for method, url, body in admin_endpoints:
        if method == "GET":
            r = await async_client.get(url, headers=headers)
        elif method == "POST":
            r = await async_client.post(url, json=body or {}, headers=headers)
        elif method == "PATCH":
            r = await async_client.patch(url, json=body or {}, headers=headers)
        elif method == "DELETE":
            r = await async_client.delete(url, headers=headers)
        else:
            raise ValueError(f"Unknown method: {method}")

        assert r.status_code == 403, (
            f"Expected 403 for {method} {url} with analyst token, got {r.status_code}: {r.text}"
        )


# ---------------------------------------------------------------------------
# 11. test_forgot_password_always_202
# ---------------------------------------------------------------------------


async def test_forgot_password_always_202(async_client: AsyncClient) -> None:
    """POST /auth/forgot-password always returns 202 regardless of email existence."""
    # Non-existent email
    r1 = await async_client.post(
        "/api/v1/auth/forgot-password",
        json={"email": "definitely-not-registered@nowhere.example"},
    )
    assert r1.status_code == 202

    # Another non-existent email (proves enumeration prevention is consistent)
    r2 = await async_client.post(
        "/api/v1/auth/forgot-password",
        json={"email": "also-not-registered@nowhere.example"},
    )
    assert r2.status_code == 202


# ---------------------------------------------------------------------------
# 12. test_reset_password_cycle
# ---------------------------------------------------------------------------


async def test_reset_password_cycle(
    async_client: AsyncClient,
    db_session: AsyncSession,
    admin_user: User,
) -> None:
    """Full password-reset cycle: token valid → new password works → replay rejected."""
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    reset = PasswordResetToken(
        id=uuid.uuid4(),
        user_id=admin_user.id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db_session.add(reset)
    await db_session.flush()

    # Consume the token and set a new password
    r1 = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": raw_token, "new_password": _NEW_PASSWORD},
    )
    assert r1.status_code == 200, r1.text

    # Can now log in with the new password
    r2 = await async_client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": _NEW_PASSWORD},
    )
    assert r2.status_code == 200, r2.text

    # Token has been consumed — replay is rejected with 422
    r3 = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": raw_token, "new_password": "yet-another-pw"},
    )
    assert r3.status_code == 422


# ---------------------------------------------------------------------------
# 13. test_login_failed_creates_audit_entry
# ---------------------------------------------------------------------------


async def test_login_failed_creates_audit_entry(
    async_client: AsyncClient,
    db_session: AsyncSession,
    admin_user: User,
) -> None:
    """Failed login creates a login_failed row in audit_log (S-06 fix)."""
    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": "wrong-password"},
    )
    assert resp.status_code == 401

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "login_failed",
            AuditLog.user_id == admin_user.id,
        )
    )
    entries = result.scalars().all()
    assert len(entries) >= 1, "Expected at least one login_failed audit log entry"
    assert entries[0].org_id == admin_user.org_id
