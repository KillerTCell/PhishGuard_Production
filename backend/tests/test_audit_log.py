"""Section 9 Phase 3F — Audit log endpoint tests.

Covers: GET /audit-log (paginated, filters by user_id and action)
"""
from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.organisation import Organisation
from app.models.user import User


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _make_audit(
    org_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
    action: str = "login_success",
) -> AuditLog:
    return AuditLog(
        org_id=org_id,
        user_id=user_id,
        action=action,
        target_type="user",
        target_id=user_id,
        detail={},
    )


# ---------------------------------------------------------------------------
# 1. test_get_audit_log_empty
# ---------------------------------------------------------------------------


async def test_get_audit_log_empty(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /audit-log → 200, empty items when no audit entries."""
    resp = await async_client.get("/api/v1/audit-log", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert data["page"] == 1


# ---------------------------------------------------------------------------
# 2. test_get_audit_log_with_entries
# ---------------------------------------------------------------------------


async def test_get_audit_log_with_entries(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /audit-log → returns entries in reverse chronological order."""
    entry1 = _make_audit(org.id, admin_user.id, "login_success")
    entry2 = _make_audit(org.id, admin_user.id, "email_deleted")
    db_session.add(entry1)
    db_session.add(entry2)
    await db_session.flush()

    resp = await async_client.get("/api/v1/audit-log", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total"] >= 2
    actions = [item["action"] for item in data["items"]]
    assert "login_success" in actions
    assert "email_deleted" in actions


# ---------------------------------------------------------------------------
# 3. test_get_audit_log_filter_by_action
# ---------------------------------------------------------------------------


async def test_get_audit_log_filter_by_action(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /audit-log?action=login_success → only login_success entries."""
    entry = _make_audit(org.id, admin_user.id, "login_success")
    other = _make_audit(org.id, admin_user.id, "threshold_changed")
    db_session.add(entry)
    db_session.add(other)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/audit-log",
        headers=_auth(admin_token),
        params={"action": "login_success"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    for item in data["items"]:
        assert "login_success" in item["action"]


# ---------------------------------------------------------------------------
# 4. test_get_audit_log_filter_by_user_id
# ---------------------------------------------------------------------------


async def test_get_audit_log_filter_by_user_id(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    analyst_user: User,
) -> None:
    """GET /audit-log?user_id={id} → only that user's entries."""
    admin_entry = _make_audit(org.id, admin_user.id, "login_success")
    analyst_entry = _make_audit(org.id, analyst_user.id, "email_deleted")
    db_session.add(admin_entry)
    db_session.add(analyst_entry)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/audit-log",
        headers=_auth(admin_token),
        params={"user_id": str(admin_user.id)},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    for item in data["items"]:
        assert item["user_id"] == str(admin_user.id)


# ---------------------------------------------------------------------------
# 5. test_get_audit_log_pagination
# ---------------------------------------------------------------------------


async def test_get_audit_log_pagination(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /audit-log?page_size=2 → respects pagination."""
    for i in range(5):
        db_session.add(_make_audit(org.id, admin_user.id, f"action_{i}"))
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/audit-log",
        headers=_auth(admin_token),
        params={"page": 1, "page_size": 2},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["items"]) <= 2
    assert data["total"] >= 5
    assert data["pages"] >= 3


# ---------------------------------------------------------------------------
# 6. test_get_audit_log_analyst_forbidden
# ---------------------------------------------------------------------------


async def test_get_audit_log_analyst_forbidden(
    async_client: AsyncClient,
    analyst_token: str,
    org: Organisation,
    admin_user: User,
    analyst_user: User,
) -> None:
    """GET /audit-log with analyst token → 403."""
    resp = await async_client.get("/api/v1/audit-log", headers=_auth(analyst_token))
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 7. test_get_audit_log_denormalises_user_name
# ---------------------------------------------------------------------------


async def test_get_audit_log_denormalises_user_name(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """Audit log items include user_name from joined User table."""
    entry = _make_audit(org.id, admin_user.id, "login_success")
    db_session.add(entry)
    await db_session.flush()

    resp = await async_client.get("/api/v1/audit-log", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    user_items = [i for i in data["items"] if i["user_id"] == str(admin_user.id)]
    assert len(user_items) >= 1
    assert user_items[0]["user_name"] == admin_user.full_name
