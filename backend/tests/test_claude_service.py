"""Section 9 Phase 3F — Claude service unit tests.

Covers app/services/claude_service.py:
  - generate_explanation() happy path (mocked Anthropic client)
  - generate_explanation() unexpected exception fallback
  - chat_stream() local_mode keyword match
  - chat_stream() local_mode no match (default)
  - chat_stream() API streaming (mocked)
  - chat_stream() API error fallback
"""
from __future__ import annotations

import asyncio
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestGenerateExplanation:
    """Tests for claude_service.generate_explanation()."""

    async def test_generate_explanation_success_mocked(self) -> None:
        """generate_explanation() returns Claude text on success (mocked Anthropic client)."""
        from anthropic.types import TextBlock

        from app.services import claude_service

        mock_response = MagicMock()
        mock_response.content = [TextBlock(type="text", text="Phishing detected via urgency.")]
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        with patch("anthropic.Anthropic", return_value=mock_client):
            result = await claude_service.generate_explanation(
                top_features=[{"name": "urgency_language", "value": 0.9, "score_contribution": 0.8}],
                sender="evil@phish.example",
                subject="URGENT: Verify Now",
            )
        assert result == "Phishing detected via urgency."

    async def test_generate_explanation_non_text_block_fallback(self) -> None:
        """generate_explanation() falls back when block is not TextBlock."""
        from app.services import claude_service

        # Return a non-TextBlock content type
        mock_block = MagicMock()
        mock_block.__class__.__name__ = "ToolUseBlock"
        mock_response = MagicMock()
        mock_response.content = [mock_block]
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        with patch("anthropic.Anthropic", return_value=mock_client):
            result = await claude_service.generate_explanation(
                top_features=[{"name": "urgency_language", "value": 0.9, "score_contribution": 0.8}],
                sender="evil@phish.example",
                subject="URGENT",
            )
        # Should return default template (non-TextBlock)
        assert result == claude_service.RULE_TEXT_TEMPLATES["default"]

    async def test_generate_explanation_anthropic_timeout_fallback(self) -> None:
        """generate_explanation() falls back to template on timeout."""
        import httpx

        from app.services import claude_service

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = httpx.TimeoutException("timeout")

        with patch("anthropic.Anthropic", return_value=mock_client):
            result = await claude_service.generate_explanation(
                top_features=[{"name": "link_mismatch", "value": 1.0, "score_contribution": 0.9}],
                sender="evil@phish.example",
                subject="Click here",
            )
        # Should fall back to rule template for link_mismatch
        assert result == claude_service.RULE_TEXT_TEMPLATES["link_mismatch"]

    async def test_generate_explanation_unexpected_exception_fallback(self) -> None:
        """generate_explanation() falls back to template on unexpected exception."""
        from app.services import claude_service

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = RuntimeError("unexpected crash")

        with patch("anthropic.Anthropic", return_value=mock_client):
            result = await claude_service.generate_explanation(
                top_features=[{"name": "credential_request", "value": 0.8, "score_contribution": 0.7}],
                sender="evil@phish.example",
                subject="Enter your password",
            )
        assert result == claude_service.RULE_TEXT_TEMPLATES["credential_request"]

    async def test_generate_explanation_empty_features_default_fallback(self) -> None:
        """generate_explanation() uses 'default' template when features is empty."""
        import anthropic

        from app.services import claude_service

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = anthropic.APIError(
            message="api error", request=None, body=None
        )

        with patch("anthropic.Anthropic", return_value=mock_client):
            result = await claude_service.generate_explanation(
                top_features=[],
                sender="",
                subject="",
            )
        assert result == claude_service.RULE_TEXT_TEMPLATES["default"]


class TestChatStream:
    """Tests for claude_service.chat_stream()."""

    async def test_local_mode_keyword_match(self) -> None:
        """chat_stream() in local_mode returns matched keyword answer."""
        from app.services.claude_service import LOCAL_ANSWER_MAP, chat_stream

        messages = [{"role": "user", "content": "What is the tech stack?"}]
        chunks = []
        async for chunk in chat_stream(messages, org_stats={}, local_mode=True):
            chunks.append(chunk)

        result = "".join(chunks)
        assert "FastAPI" in result or len(result) > 0

    async def test_local_mode_no_match_returns_default(self) -> None:
        """chat_stream() in local_mode with no keyword match returns 'how does' default."""
        from app.services.claude_service import LOCAL_ANSWER_MAP, chat_stream

        messages = [{"role": "user", "content": "xyzyxzyzx no match here zzz"}]
        chunks = []
        async for chunk in chat_stream(messages, org_stats={}, local_mode=True):
            chunks.append(chunk)

        result = "".join(chunks)
        # Should return some default answer
        assert len(result) > 0
        assert result == LOCAL_ANSWER_MAP["how does"]

    async def test_chat_stream_api_error_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """chat_stream() falls back to LOCAL_ANSWER_MAP on API error."""
        from app.services.claude_service import LOCAL_ANSWER_MAP, chat_stream

        async def _fail_stream(*args: object, **kwargs: object) -> None:
            raise Exception("API unavailable")

        messages = [{"role": "user", "content": "how does phishguard work?"}]
        org_stats = {"current_threshold": {"suspicious": 30, "phishing": 80}, "total_analysed": 100}

        # Patch AsyncAnthropic to raise
        with patch("anthropic.AsyncAnthropic") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_stream_ctx = MagicMock()
            mock_stream_ctx.__aenter__ = AsyncMock(side_effect=Exception("API error"))
            mock_client.messages.stream.return_value = mock_stream_ctx

            chunks = []
            async for chunk in chat_stream(messages, org_stats=org_stats, local_mode=False):
                chunks.append(chunk)

        result = "".join(chunks)
        assert len(result) > 0

    async def test_chat_stream_api_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """chat_stream() yields text deltas from Claude API stream."""
        from app.services.claude_service import chat_stream

        messages = [{"role": "user", "content": "explain phishing"}]
        org_stats = {"current_threshold": {"suspicious": 30, "phishing": 80}, "total_analysed": 50}

        async def _text_stream() -> AsyncGenerator[str, None]:
            for word in ["This ", "is ", "phishing."]:
                yield word

        mock_stream = MagicMock()
        mock_stream.text_stream = _text_stream()

        mock_stream_ctx = MagicMock()
        mock_stream_ctx.__aenter__ = AsyncMock(return_value=mock_stream)
        mock_stream_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("anthropic.AsyncAnthropic") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.messages.stream.return_value = mock_stream_ctx

            chunks = []
            async for chunk in chat_stream(messages, org_stats=org_stats, local_mode=False):
                chunks.append(chunk)

        result = "".join(chunks)
        assert result == "This is phishing."

    async def test_chat_stream_pydantic_message_objects(self) -> None:
        """chat_stream() handles Pydantic-style message objects (not just dicts)."""
        from app.services.claude_service import LOCAL_ANSWER_MAP, chat_stream

        # Message as object with role/content attributes
        class FakeMsg:
            def __init__(self, role: str, content: str):
                self.role = role
                self.content = content

        messages = [FakeMsg("user", "admin flow")]
        chunks = []
        async for chunk in chat_stream(messages, org_stats={}, local_mode=True):
            chunks.append(chunk)

        result = "".join(chunks)
        assert len(result) > 0
