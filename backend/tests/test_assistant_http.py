"""Section 9 Phase 3F — AI assistant HTTP endpoint tests.

Covers missing lines in assistant.py:
  - POST /analysis/assistant local_mode=True (lines 175-185)
  - POST /analysis/assistant local_mode=False with mocked Claude (lines 186-205)
  - _build_context() with org_stats from Redis (lines 137-150)
  - _stream_local (lines 88-90)
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

from app.models.organisation import Organisation
from app.models.user import User


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. POST /analysis/assistant local_mode=True
# ---------------------------------------------------------------------------


async def test_assistant_chat_local_mode_keyword_match(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /analysis/assistant local_mode=True with keyword → SSE data stream."""
    resp = await async_client.post(
        "/api/v1/analysis/assistant",
        headers=_auth(admin_token),
        json={
            "messages": [{"role": "user", "content": "What is the tech stack?"}],
            "local_mode": True,
        },
    )
    assert resp.status_code == 200, resp.text
    # SSE response content type
    assert "text/event-stream" in resp.headers.get("content-type", "")
    text = resp.text
    assert "data:" in text
    assert "[DONE]" in text


async def test_assistant_chat_local_mode_no_match(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /analysis/assistant local_mode=True with no keyword → default answer."""
    resp = await async_client.post(
        "/api/v1/analysis/assistant",
        headers=_auth(admin_token),
        json={
            "messages": [{"role": "user", "content": "xyzxyzxyz no match"}],
            "local_mode": True,
        },
    )
    assert resp.status_code == 200, resp.text
    assert "[DONE]" in resp.text


# ---------------------------------------------------------------------------
# 2. POST /analysis/assistant local_mode=False with mocked Claude
# ---------------------------------------------------------------------------


async def test_assistant_chat_api_mode_mocked(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
    redis_mock,
) -> None:
    """POST /analysis/assistant API mode streams mocked Claude text."""
    async def _text_gen():
        for word in ["This ", "is ", "a ", "test."]:
            yield word

    mock_stream = MagicMock()
    mock_stream.text_stream = _text_gen()
    mock_stream_ctx = MagicMock()
    mock_stream_ctx.__aenter__ = AsyncMock(return_value=mock_stream)
    mock_stream_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("anthropic.AsyncAnthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.stream.return_value = mock_stream_ctx

        resp = await async_client.post(
            "/api/v1/analysis/assistant",
            headers=_auth(admin_token),
            json={
                "messages": [{"role": "user", "content": "explain phishing"}],
                "local_mode": False,
            },
        )

    assert resp.status_code == 200, resp.text
    assert "text/event-stream" in resp.headers.get("content-type", "")
    text = resp.text
    assert "data:" in text


async def test_assistant_chat_api_mode_with_cached_stats(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
    redis_mock,
) -> None:
    """POST /analysis/assistant with org stats in Redis → _build_context uses them."""
    # Pre-load stats into fakeredis
    stats_data = {
        "total_analysed": 100,
        "quarantined_count": 10,
        "safe_count": 85,
        "suspicious_count": 5,
        "has_pending_quarantine": False,
        "feedback_count": 20,
    }
    await redis_mock.set(f"stats:{org.id}:all_time", json.dumps(stats_data))

    async def _text_gen():
        yield "Context "
        yield "aware."

    mock_stream = MagicMock()
    mock_stream.text_stream = _text_gen()
    mock_stream_ctx = MagicMock()
    mock_stream_ctx.__aenter__ = AsyncMock(return_value=mock_stream)
    mock_stream_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("anthropic.AsyncAnthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.stream.return_value = mock_stream_ctx

        resp = await async_client.post(
            "/api/v1/analysis/assistant",
            headers=_auth(admin_token),
            json={
                "messages": [{"role": "user", "content": "how many emails?"}],
                "local_mode": False,
            },
        )

    assert resp.status_code == 200, resp.text


async def test_assistant_chat_api_mode_fallback_on_error(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
    redis_mock,
) -> None:
    """POST /analysis/assistant API error → falls back to local answer."""
    with patch("anthropic.AsyncAnthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(side_effect=Exception("Claude API down"))
        mock_client.messages.stream.return_value = mock_ctx

        resp = await async_client.post(
            "/api/v1/analysis/assistant",
            headers=_auth(admin_token),
            json={
                "messages": [{"role": "user", "content": "tech stack"}],
                "local_mode": False,
            },
        )

    assert resp.status_code == 200, resp.text
    text = resp.text
    assert "data:" in text
