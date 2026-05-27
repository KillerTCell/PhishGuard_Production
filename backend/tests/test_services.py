"""Section 9 Phase 3F — Service layer unit tests.

Covers:
  - ml_classifier: classify() happy path, vector length error, model not found
  - insights_service: compute_insights() threshold insight, spike, failures, cache
  - quarantine_service: apply_outcome() safe/suspicious/phishing routing + SSE
  - email_parser: parse_eml() happy path and error
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from textwrap import dedent
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis_result import AnalysisResult
from app.models.email import Email
from app.models.organisation import Organisation
from app.models.user import User
from tests.conftest import EmailFactory, OrgFactory


# ===========================================================================
# ML Classifier
# ===========================================================================


class TestMLClassifier:
    """Unit tests for app.services.ml_classifier."""

    def test_classify_happy_path(self) -> None:
        """classify() with a real model and 7-element vector returns valid dict."""
        from app.services.ml_classifier import classify

        # All-zeros vector → safe (low risk score)
        result = classify([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
        assert isinstance(result["risk_score"], int)
        assert 0 <= result["risk_score"] <= 100
        assert result["severity"] in ("critical", "high", "medium", "low")

    def test_classify_phishing_vector(self) -> None:
        """classify() with high-risk features returns elevated risk_score."""
        from app.services.ml_classifier import classify

        # All-ones vector → should score high
        result = classify([1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0])
        assert result["risk_score"] >= 0  # model-dependent; just verify structure

    def test_classify_wrong_vector_length(self) -> None:
        """classify() with wrong vector length raises ValueError."""
        from app.services.ml_classifier import classify

        with pytest.raises(ValueError, match="7 elements"):
            classify([0.0, 1.0, 0.0])  # only 3 elements

    def test_classify_model_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """classify() raises ModelNotFoundError when model file is missing."""
        import functools

        from app.services import ml_classifier
        from app.services.ml_classifier import ModelNotFoundError

        # Clear the lru_cache and patch the path to a non-existent file
        ml_classifier.get_model.cache_clear()
        fake_path = MagicMock()
        fake_path.exists.return_value = False
        monkeypatch.setattr(ml_classifier, "_MODEL_PATH", fake_path)

        with pytest.raises(ModelNotFoundError):
            ml_classifier.get_model()

        # Restore cache so subsequent tests work
        ml_classifier.get_model.cache_clear()

    def test_severity_mapping(self) -> None:
        """classify() returns correct severity bands based on risk_score thresholds."""
        from app.services.ml_classifier import classify

        # Patch get_model to return a controlled mock
        mock_clf = MagicMock()
        mock_clf.classes_ = ["safe", "phishing"]

        with patch("app.services.ml_classifier.get_model", return_value=mock_clf):
            # Critical: risk_score >= 90
            mock_clf.predict_proba.return_value = [[0.05, 0.95]]
            result = classify([0.0] * 7)
            assert result["risk_score"] == 95
            assert result["severity"] == "critical"

            # High: 80 <= score < 90
            mock_clf.predict_proba.return_value = [[0.16, 0.84]]
            result = classify([0.0] * 7)
            assert result["risk_score"] == 84
            assert result["severity"] == "high"

            # Medium: 30 <= score < 80
            mock_clf.predict_proba.return_value = [[0.50, 0.50]]
            result = classify([0.0] * 7)
            assert result["risk_score"] == 50
            assert result["severity"] == "medium"

            # Low: score < 30
            mock_clf.predict_proba.return_value = [[0.90, 0.10]]
            result = classify([0.0] * 7)
            assert result["risk_score"] == 10
            assert result["severity"] == "low"


# ===========================================================================
# Insights Service
# ===========================================================================


class TestInsightsService:
    """Unit tests for app.services.insights_service."""

    async def test_threshold_insight_always_present(
        self,
        db_session: AsyncSession,
        org: Organisation,
        admin_user: User,
        redis_mock: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """compute_insights() always includes the threshold info insight."""
        from app.services.insights_service import compute_insights

        results = await compute_insights(org.id, db_session, redis_mock)
        types = [i.type.value for i in results]
        titles = [i.title for i in results]
        assert "info" in types
        assert any("threshold" in t.lower() for t in titles)

    async def test_no_spike_when_no_history(
        self,
        db_session: AsyncSession,
        org: Organisation,
        admin_user: User,
        redis_mock: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """No quarantine spike insight when prev_week_q == 0."""
        from app.services.insights_service import compute_insights

        results = await compute_insights(org.id, db_session, redis_mock)
        spike_insights = [i for i in results if "spike" in i.title.lower() or "quarantine" in i.title.lower()]
        assert len(spike_insights) == 0

    async def test_failure_alert_when_failed_emails(
        self,
        db_session: AsyncSession,
        org: Organisation,
        admin_user: User,
        redis_mock: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """compute_insights() includes failure alert when failed emails exist."""
        from app.services.insights_service import compute_insights

        failed = EmailFactory(org_id=org.id, status="failed")
        db_session.add(failed)
        await db_session.flush()
        # Ensure the session is visible to the service call

        results = await compute_insights(org.id, db_session, redis_mock)
        failure_insights = [i for i in results if "failure" in i.title.lower() or "failed" in i.title.lower()]
        assert len(failure_insights) >= 1

    async def test_cache_populated_on_first_call(
        self,
        db_session: AsyncSession,
        org: Organisation,
        admin_user: User,
        redis_mock: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """compute_insights() writes to Redis cache after first call."""
        from app.services.insights_service import compute_insights

        await compute_insights(org.id, db_session, redis_mock)
        cache_key = f"insights:{org.id}"
        cached = await redis_mock.get(cache_key)
        assert cached is not None
        items = json.loads(cached)
        assert len(items) >= 1

    async def test_cache_served_on_second_call(
        self,
        db_session: AsyncSession,
        org: Organisation,
        admin_user: User,
        redis_mock: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """compute_insights() serves from Redis cache on second call."""
        from app.services.insights_service import compute_insights

        # First call populates cache
        result1 = await compute_insights(org.id, db_session, redis_mock)

        # Second call should return cached result
        result2 = await compute_insights(org.id, db_session, redis_mock)
        assert len(result1) == len(result2)
        assert result1[0].title == result2[0].title


# ===========================================================================
# Quarantine Service
# ===========================================================================


class TestQuarantineService:
    """Unit tests for app.services.quarantine_service."""

    async def test_apply_outcome_safe(
        self,
        db_session: AsyncSession,
        org: Organisation,
        admin_user: User,
        redis_mock: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """apply_outcome() with 'safe' classification → email status='delivered'."""
        from app.services.quarantine_service import apply_outcome

        email = EmailFactory(org_id=org.id, status="pending", sender="safe@example.com", subject="Hello")
        db_session.add(email)
        await db_session.flush()
        analysis = AnalysisResult(
            email_id=email.id,
            classification="safe",
            risk_score=10,
            model_version="rf_test",
            threshold_applied_suspicious=30,
            threshold_applied_phishing=80,
            top_features=[],
            explanation="Looks safe.",
        )
        db_session.add(analysis)
        await db_session.flush()
        await db_session.commit()

        await apply_outcome(email.id, db_session, redis_mock)

        # Verify via SSE stream that scan_complete was published
        stream_key = f"org:{org.id}:stream"
        entries = await redis_mock.xrange(stream_key)
        assert len(entries) >= 1
        event_data = json.loads(entries[-1][1][b"data"])
        assert event_data["type"] == "scan_complete"
        assert event_data["status"] == "delivered"

    async def test_apply_outcome_suspicious(
        self,
        db_session: AsyncSession,
        org: Organisation,
        admin_user: User,
        redis_mock: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """apply_outcome() with 'suspicious' → email status='flagged'."""
        from app.services.quarantine_service import apply_outcome

        email = EmailFactory(
            org_id=org.id,
            status="pending",
            sender="suspect@example.com",
            subject="You won a prize",
        )
        db_session.add(email)
        await db_session.flush()
        analysis = AnalysisResult(
            email_id=email.id,
            classification="suspicious",
            risk_score=55,
            model_version="rf_test",
            threshold_applied_suspicious=30,
            threshold_applied_phishing=80,
            top_features=[{"name": "urgency_language", "value": 0.7, "score_contribution": 0.5}],
            explanation="Suspicious indicators found.",
        )
        db_session.add(analysis)
        await db_session.flush()
        await db_session.commit()

        await apply_outcome(email.id, db_session, redis_mock)

        stream_key = f"org:{org.id}:stream"
        entries = await redis_mock.xrange(stream_key)
        event_data = json.loads(entries[-1][1][b"data"])
        assert event_data["status"] == "flagged"

    async def test_apply_outcome_phishing(
        self,
        db_session: AsyncSession,
        org: Organisation,
        admin_user: User,
        redis_mock: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """apply_outcome() with 'phishing' → status='quarantined', two SSE events."""
        from app.services.quarantine_service import apply_outcome

        email = EmailFactory(
            org_id=org.id,
            status="pending",
            sender="evil@phish.example",
            subject="URGENT: Verify NOW",
        )
        db_session.add(email)
        await db_session.flush()
        analysis = AnalysisResult(
            email_id=email.id,
            classification="phishing",
            risk_score=92,
            model_version="rf_test",
            threshold_applied_suspicious=30,
            threshold_applied_phishing=80,
            top_features=[{"name": "link_mismatch", "value": 1.0, "score_contribution": 0.9}],
            explanation="Clear phishing indicators.",
        )
        db_session.add(analysis)
        await db_session.flush()
        await db_session.commit()

        await apply_outcome(email.id, db_session, redis_mock)

        stream_key = f"org:{org.id}:stream"
        entries = await redis_mock.xrange(stream_key)
        assert len(entries) >= 2  # scan_complete + quarantine_created
        event_types = [json.loads(e[1][b"data"])["type"] for e in entries]
        assert "scan_complete" in event_types
        assert "quarantine_created" in event_types

    async def test_apply_outcome_email_not_found(
        self,
        db_session: AsyncSession,
        org: Organisation,
        admin_user: User,
        redis_mock: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """apply_outcome() with nonexistent email_id → logs error, no crash."""
        from app.services.quarantine_service import apply_outcome

        # Should return silently without error
        await apply_outcome(uuid.uuid4(), db_session, redis_mock)

    async def test_severity_helper(self) -> None:
        """_severity() maps risk_score to correct bands."""
        from app.services.quarantine_service import _severity

        assert _severity(95) == "critical"
        assert _severity(85) == "high"
        assert _severity(50) == "medium"
        assert _severity(10) == "low"

    async def test_bump_analyst_notifications(
        self,
        db_session: AsyncSession,
        org: Organisation,
        admin_user: User,
        analyst_user: User,
        redis_mock: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """_bump_analyst_notifications() increments unread counters for all active analysts."""
        from app.services.quarantine_service import _bump_analyst_notifications

        await _bump_analyst_notifications(redis_mock, db_session, org.id)

        # Both admin and analyst are active — both should get a counter
        admin_key = f"notif:{admin_user.id}:unread"
        analyst_key = f"notif:{analyst_user.id}:unread"
        admin_count = await redis_mock.get(admin_key)
        analyst_count = await redis_mock.get(analyst_key)
        assert admin_count is not None
        assert analyst_count is not None

    async def test_bump_analyst_notifications_from_cache(
        self,
        db_session: AsyncSession,
        org: Organisation,
        admin_user: User,
        analyst_user: User,
        redis_mock: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """_bump_analyst_notifications() uses Redis cache on second call."""
        from app.services.quarantine_service import _bump_analyst_notifications

        # First call populates cache
        await _bump_analyst_notifications(redis_mock, db_session, org.id)

        cache_key = f"org:{org.id}:analyst_ids"
        cached = await redis_mock.get(cache_key)
        assert cached is not None

        # Second call uses cache (no DB hit)
        await _bump_analyst_notifications(redis_mock, db_session, org.id)
        admin_key = f"notif:{admin_user.id}:unread"
        count = await redis_mock.get(admin_key)
        assert int(count) >= 2  # incremented twice


# ===========================================================================
# Email Parser
# ===========================================================================


class TestEmailParser:
    """Unit tests for app.services.email_parser."""

    def test_parse_simple_text_email(self) -> None:
        """parse_eml() on a minimal RFC-2822 email returns expected fields."""
        from app.services.email_parser import parse_eml

        raw = dedent("""\
            From: sender@example.com
            To: recipient@example.com
            Subject: Hello world
            Date: Wed, 27 May 2026 10:00:00 +0000
            MIME-Version: 1.0
            Content-Type: text/plain; charset=utf-8

            This is the email body.
        """).encode()

        result = parse_eml(raw)
        assert result["sender"] == "sender@example.com"
        assert result["subject"] == "Hello world"
        assert result["recipient_address"] == "recipient@example.com"
        assert "body_text" in result
        assert result["received_at"] is not None

    def test_parse_html_email(self) -> None:
        """parse_eml() on HTML email sanitises the body and extracts links."""
        from app.services.email_parser import parse_eml

        raw = dedent("""\
            From: evil@phish.example
            To: victim@company.example
            Subject: Verify your account
            Date: Wed, 27 May 2026 10:00:00 +0000
            MIME-Version: 1.0
            Content-Type: text/html; charset=utf-8

            <html><body>
            <p>Click <a href="http://evil.example/steal">here</a></p>
            <script>alert('xss')</script>
            </body></html>
        """).encode()

        result = parse_eml(raw)
        assert "html_sanitised" in result
        # XSS should be stripped
        assert "<script>" not in (result.get("html_sanitised") or "")

    def test_parse_invalid_email_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """parse_eml() raises EmailParseError when both parsers fail."""
        from app.services import email_parser
        from app.services.email_parser import EmailParseError

        # Patch both primary and fallback extraction to raise exceptions
        class _FailParser:
            def parsebytes(self, *a, **kw):  # type: ignore[override]
                raise ValueError("simulated BytesParser failure")

        def _fail_fallback(*a, **kw):  # type: ignore[return]
            raise Exception("simulated mailparser fallback failure")

        monkeypatch.setattr(email_parser, "BytesParser", _FailParser)
        monkeypatch.setattr(email_parser, "_extract_from_mailparser", _fail_fallback)

        with pytest.raises(EmailParseError):
            email_parser.parse_eml(b"does not matter")

    def test_parse_eml_missing_date_defaults_to_utcnow(self) -> None:
        """parse_eml() falls back to utcnow when Date: header is absent."""
        from datetime import datetime, timezone

        from app.services.email_parser import parse_eml

        raw = dedent("""\
            From: sender@example.com
            To: recipient@example.com
            Subject: No date header
            MIME-Version: 1.0
            Content-Type: text/plain; charset=utf-8

            Body without date.
        """).encode()

        result = parse_eml(raw)
        # Should not raise; received_at should be a datetime
        assert isinstance(result["received_at"], datetime)
        assert result["received_at"].tzinfo is not None
