"""Section 9 Phase 1H — Health endpoint tests (4 tests).

All tests use the async_client fixture which wires the FastAPI app to an
in-transaction PostgreSQL session and a fresh FakeRedis instance.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app as _app


# ---------------------------------------------------------------------------
# 1. test_health_ok
# ---------------------------------------------------------------------------


async def test_health_ok(async_client: AsyncClient) -> None:
    """GET /health with live DB and Redis → 200, db='ok', redis='ok'."""
    resp = await async_client.get("/api/v1/health")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["db"] == "ok"
    assert data["redis"] == "ok"
    assert data["status"] == "ok"
    assert "timestamp" in data
    assert "version" in data
    assert "model_loaded" in data


# ---------------------------------------------------------------------------
# 2. test_health_db_down
# ---------------------------------------------------------------------------


async def test_health_db_down(async_client: AsyncClient) -> None:
    """GET /health with a broken DB session → 503, status='error', db='error'."""
    from app.dependencies import get_db

    async def _broken_db():
        """Yield a session whose execute() always raises."""

        class _BrokenSession:
            async def execute(self, *args, **kwargs):
                raise RuntimeError("simulated DB failure")

        yield _BrokenSession()

    original = _app.dependency_overrides.get(get_db)
    _app.dependency_overrides[get_db] = _broken_db
    try:
        resp = await async_client.get("/api/v1/health")
    finally:
        if original is not None:
            _app.dependency_overrides[get_db] = original
        else:
            _app.dependency_overrides.pop(get_db, None)

    assert resp.status_code == 503, resp.text
    data = resp.json()
    assert data["db"] == "error"
    assert data["status"] == "error"


# ---------------------------------------------------------------------------
# 3. test_health_redis_down
# ---------------------------------------------------------------------------


async def test_health_redis_down(async_client: AsyncClient) -> None:
    """GET /health with a broken Redis connection → 503, status='error', redis='error'."""
    from app.dependencies import get_redis

    class _BrokenRedis:
        async def ping(self, *args, **kwargs):
            raise RuntimeError("simulated Redis failure")

    async def _broken_redis():
        return _BrokenRedis()

    original = _app.dependency_overrides.get(get_redis)
    _app.dependency_overrides[get_redis] = _broken_redis
    try:
        resp = await async_client.get("/api/v1/health")
    finally:
        if original is not None:
            _app.dependency_overrides[get_redis] = original
        else:
            _app.dependency_overrides.pop(get_redis, None)

    assert resp.status_code == 503, resp.text
    data = resp.json()
    assert data["redis"] == "error"
    assert data["status"] == "error"


# ---------------------------------------------------------------------------
# 4. test_health_no_auth_required
# ---------------------------------------------------------------------------


async def test_health_no_auth_required(async_client: AsyncClient) -> None:
    """GET /health without Authorization header → not 401 (public endpoint)."""
    resp = await async_client.get("/api/v1/health")
    # Must not require auth — any 2xx or 503 (if infra down) is acceptable,
    # but 401 / 403 would indicate the endpoint is incorrectly protected.
    assert resp.status_code != 401, "Health endpoint must not require authentication"
    assert resp.status_code != 403, "Health endpoint must not require authentication"
