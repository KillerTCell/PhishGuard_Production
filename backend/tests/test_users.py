"""Section 9 Phase 3F — User management endpoint tests.

Covers: GET /users/stats, GET /users, GET /users/{id},
        PATCH /users/{id}, DELETE /users/{id}
"""
from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.organisation import Organisation
from app.models.user import User
from tests.conftest import UserFactory


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. test_user_stats
# ---------------------------------------------------------------------------


async def test_user_stats(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    analyst_user: User,
) -> None:
    """GET /users/stats → correct aggregate counts."""
    resp = await async_client.get("/api/v1/users/stats", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total"] >= 2
    assert data["admins"] >= 1
    assert data["analysts"] >= 1
    assert data["active"] >= 2


# ---------------------------------------------------------------------------
# 2. test_list_users
# ---------------------------------------------------------------------------


async def test_list_users(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    analyst_user: User,
) -> None:
    """GET /users → list of org users including both fixtures."""
    resp = await async_client.get("/api/v1/users", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert isinstance(data, list)
    ids = [u["id"] for u in data]
    assert str(admin_user.id) in ids
    assert str(analyst_user.id) in ids


# ---------------------------------------------------------------------------
# 3. test_list_users_analyst_forbidden
# ---------------------------------------------------------------------------


async def test_list_users_analyst_forbidden(
    async_client: AsyncClient,
    analyst_token: str,
    org: Organisation,
    admin_user: User,
    analyst_user: User,
) -> None:
    """GET /users with analyst token → 403."""
    resp = await async_client.get("/api/v1/users", headers=_auth(analyst_token))
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 4. test_get_user_detail
# ---------------------------------------------------------------------------


async def test_get_user_detail(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /users/{id} → 200 with profile and audit actions list."""
    resp = await async_client.get(
        f"/api/v1/users/{admin_user.id}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["id"] == str(admin_user.id)
    assert data["email"] == admin_user.email
    assert data["role"] == "admin"
    assert "recent_audit_actions" in data
    assert isinstance(data["recent_audit_actions"], list)


# ---------------------------------------------------------------------------
# 5. test_get_user_not_found
# ---------------------------------------------------------------------------


async def test_get_user_not_found(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /users/{nonexistent_id} → 404."""
    resp = await async_client.get(
        f"/api/v1/users/{uuid.uuid4()}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 6. test_update_user_role
# ---------------------------------------------------------------------------


async def test_update_user_role(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    analyst_user: User,
) -> None:
    """PATCH /users/{id} with role change → 200, updated role."""
    resp = await async_client.patch(
        f"/api/v1/users/{analyst_user.id}",
        headers=_auth(admin_token),
        json={"role": "admin"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["role"] == "admin"


# ---------------------------------------------------------------------------
# 7. test_update_user_deactivate
# ---------------------------------------------------------------------------


async def test_update_user_deactivate(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    analyst_user: User,
) -> None:
    """PATCH /users/{id} with is_active=False → 200, user deactivated."""
    resp = await async_client.patch(
        f"/api/v1/users/{analyst_user.id}",
        headers=_auth(admin_token),
        json={"is_active": False},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["is_active"] is False


# ---------------------------------------------------------------------------
# 8. test_update_user_cannot_self_deactivate
# ---------------------------------------------------------------------------


async def test_update_user_cannot_self_deactivate(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """PATCH /users/{own_id} with is_active=False → 403."""
    resp = await async_client.patch(
        f"/api/v1/users/{admin_user.id}",
        headers=_auth(admin_token),
        json={"is_active": False},
    )
    assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# 9. test_update_user_not_found
# ---------------------------------------------------------------------------


async def test_update_user_not_found(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """PATCH /users/{nonexistent_id} → 404."""
    resp = await async_client.patch(
        f"/api/v1/users/{uuid.uuid4()}",
        headers=_auth(admin_token),
        json={"role": "analyst"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 10. test_deactivate_user_soft_delete
# ---------------------------------------------------------------------------


async def test_deactivate_user_soft_delete(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    analyst_user: User,
) -> None:
    """DELETE /users/{id} → 204, user is_active becomes False."""
    resp = await async_client.delete(
        f"/api/v1/users/{analyst_user.id}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 204, resp.text

    # The user still exists but is deactivated
    detail_resp = await async_client.get(
        f"/api/v1/users/{analyst_user.id}",
        headers=_auth(admin_token),
    )
    assert detail_resp.status_code == 200
    assert detail_resp.json()["is_active"] is False


# ---------------------------------------------------------------------------
# 11. test_deactivate_user_not_found
# ---------------------------------------------------------------------------


async def test_deactivate_user_not_found(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """DELETE /users/{nonexistent_id} → 404."""
    resp = await async_client.delete(
        f"/api/v1/users/{uuid.uuid4()}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 12. test_user_stats_analyst_forbidden
# ---------------------------------------------------------------------------


async def test_user_stats_analyst_forbidden(
    async_client: AsyncClient,
    analyst_token: str,
    org: Organisation,
    admin_user: User,
    analyst_user: User,
) -> None:
    """GET /users/stats with analyst token → 403."""
    resp = await async_client.get("/api/v1/users/stats", headers=_auth(analyst_token))
    assert resp.status_code == 403
