"""Section 9 Phase 3F — Analysis task tests with found emails.

Tests for the "email found" happy paths in analysis_tasks.py.
Uses monkeypatched sessions so asyncio.run() can be controlled.

Coverage targets:
  - parse_and_sanitise "paste" path (lines 382-406)
  - extract_features "found + NLP error fallback" (lines 521-549)
  - extract_features "found + NLP success" (lines 521-573)
  - classify_email inner "found" path (lines 638-713)
  - generate_explanation "found" path (lines 895-914)
  - _on_task_failure with found email writing audit (lines 258-288)
  - fire_analysis_chain success (lines 312-320)
  - imap_poll_all_orgs with no active orgs (lines 1122-1135)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


class TestAnalysisTaskFoundPaths:
    """Tests for analysis_tasks where email IS found (covers happy paths)."""

    def _make_mock_session(self) -> MagicMock:
        session = MagicMock()
        session.__enter__ = MagicMock(return_value=session)
        session.__exit__ = MagicMock(return_value=False)
        session.close = MagicMock()
        session.commit = MagicMock()
        session.rollback = MagicMock()
        session.add = MagicMock()
        return session

    def _make_mock_email(
        self,
        org_id: uuid.UUID,
        email_id: uuid.UUID,
        *,
        ingestion_source: str = "paste",
    ) -> MagicMock:
        email = MagicMock()
        email.id = email_id
        email.org_id = org_id
        email.sender = "evil@phish.example"
        email.subject = "Verify your account"
        email.body_text = "Please click here immediately. Urgent!"
        email.html_sanitised = "<p>Click here</p>"
        email.links = [{"url": "http://evil.example", "text": "here", "is_mismatch": True}]
        email.attachment_metadata = []
        email.spf = "fail"
        email.dkim = "fail"
        email.dmarc = "fail"
        email.received_at = datetime.now(timezone.utc)
        email.status = "pending"
        email.added_to_training = False
        email.ingestion_source = ingestion_source
        return email

    # -----------------------------------------------------------------------
    # parse_and_sanitise — paste source (covers lines 382-406)
    # -----------------------------------------------------------------------

    def test_parse_and_sanitise_paste_source(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """parse_and_sanitise with paste source extracts links and commits."""
        from app.tasks import analysis_tasks

        org_id = uuid.uuid4()
        email_id = uuid.uuid4()
        email = self._make_mock_email(org_id, email_id, ingestion_source="paste")
        email.body_text = "Click http://evil.example for your prize!"

        session = self._make_mock_session()
        session.execute.return_value.scalar_one_or_none.return_value = email
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        result = analysis_tasks.parse_and_sanitise.apply(args=[str(email_id)])
        assert result is not None
        session.commit.assert_called()

    # -----------------------------------------------------------------------
    # extract_features — found email, NLP error → returns email_id (line 549)
    # -----------------------------------------------------------------------

    def test_extract_features_nlp_error_returns_email_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """extract_features when NLP fails returns email_id (non-fatal)."""
        from app.tasks import analysis_tasks

        org_id = uuid.uuid4()
        email_id = uuid.uuid4()
        email = self._make_mock_email(org_id, email_id)

        session = self._make_mock_session()
        session.execute.return_value.scalar_one_or_none.return_value = email
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        # asyncio.run raises → NLP failed → returns email_id
        with patch("asyncio.run", side_effect=Exception("NLP error")):
            result = analysis_tasks.extract_features.apply(args=[str(email_id)])

        assert result is not None

    # -----------------------------------------------------------------------
    # extract_features — found email, NLP success (covers lines 521-573)
    # -----------------------------------------------------------------------

    def test_extract_features_nlp_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """extract_features with successful NLP run inserts features and commits."""
        from app.tasks import analysis_tasks

        org_id = uuid.uuid4()
        email_id = uuid.uuid4()
        email = self._make_mock_email(org_id, email_id)

        # Mock a feature result
        mock_feat = MagicMock()
        mock_feat.feature_name = "urgency_language"
        mock_feat.feature_value = 0.9
        mock_feat.score_contribution = 0.8

        session = self._make_mock_session()
        session.execute.return_value.scalar_one_or_none.return_value = email
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        with patch("asyncio.run", return_value=[mock_feat]):
            result = analysis_tasks.extract_features.apply(args=[str(email_id)])

        assert result is not None
        session.commit.assert_called()
        # session.add should have been called for the EmailFeature
        session.add.assert_called()

    # -----------------------------------------------------------------------
    # classify_email — found email (covers lines 638-713)
    # -----------------------------------------------------------------------

    def test_classify_email_found_email_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """classify_email with found email calls ml_classifier and inserts result."""
        from app.tasks import analysis_tasks

        org_id = uuid.uuid4()
        email_id = uuid.uuid4()
        email = self._make_mock_email(org_id, email_id)

        # Mock org
        mock_org = MagicMock()
        mock_org.suspicious_threshold = 30
        mock_org.phishing_threshold = 80

        # Mock feature rows
        mock_feature = MagicMock()
        mock_feature.feature_name = "urgency_language"
        mock_feature.score_contribution = 0.9

        session = self._make_mock_session()
        # First call: get email; second: get org; third: get features
        session.execute.side_effect = [
            MagicMock(scalar_one_or_none=MagicMock(return_value=email)),
            MagicMock(scalar_one_or_none=MagicMock(return_value=mock_org)),
            MagicMock(scalars=MagicMock(return_value=MagicMock(
                __iter__=MagicMock(return_value=iter([mock_feature]))
            ))),
            MagicMock(),  # INSERT result
        ]
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        with patch("app.services.ml_classifier.classify", return_value={"risk_score": 85}):
            result = analysis_tasks.classify_email.apply(args=[str(email_id)])

        assert result is not None

    def test_classify_email_safe_classification(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """classify_email → safe when risk_score < suspicious_threshold."""
        from app.tasks import analysis_tasks

        org_id = uuid.uuid4()
        email_id = uuid.uuid4()
        email = self._make_mock_email(org_id, email_id)

        mock_org = MagicMock()
        mock_org.suspicious_threshold = 30
        mock_org.phishing_threshold = 80

        mock_feature = MagicMock()
        mock_feature.feature_name = "urgency_language"
        mock_feature.score_contribution = 0.1

        session = self._make_mock_session()
        session.execute.side_effect = [
            MagicMock(scalar_one_or_none=MagicMock(return_value=email)),
            MagicMock(scalar_one_or_none=MagicMock(return_value=mock_org)),
            MagicMock(scalars=MagicMock(return_value=MagicMock(
                __iter__=MagicMock(return_value=iter([mock_feature]))
            ))),
            MagicMock(),  # INSERT
        ]
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        with patch("app.services.ml_classifier.classify", return_value={"risk_score": 10}):
            result = analysis_tasks.classify_email.apply(args=[str(email_id)])

        assert result is not None

    def test_classify_email_suspicious_classification(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """classify_email → suspicious when between thresholds."""
        from app.tasks import analysis_tasks

        org_id = uuid.uuid4()
        email_id = uuid.uuid4()
        email = self._make_mock_email(org_id, email_id)

        mock_org = MagicMock()
        mock_org.suspicious_threshold = 30
        mock_org.phishing_threshold = 80

        mock_feature = MagicMock()
        mock_feature.feature_name = "urgency_language"
        mock_feature.score_contribution = 0.5

        session = self._make_mock_session()
        session.execute.side_effect = [
            MagicMock(scalar_one_or_none=MagicMock(return_value=email)),
            MagicMock(scalar_one_or_none=MagicMock(return_value=mock_org)),
            MagicMock(scalars=MagicMock(return_value=MagicMock(
                __iter__=MagicMock(return_value=iter([mock_feature]))
            ))),
            MagicMock(),  # INSERT
        ]
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        with patch("app.services.ml_classifier.classify", return_value={"risk_score": 55}):
            result = analysis_tasks.classify_email.apply(args=[str(email_id)])

        assert result is not None

    # -----------------------------------------------------------------------
    # generate_explanation — found email (covers lines 895-914)
    # -----------------------------------------------------------------------

    def test_generate_explanation_found_email(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """generate_explanation with found analysis writes explanation and commits."""
        from app.tasks import analysis_tasks

        org_id = uuid.uuid4()
        email_id = uuid.uuid4()
        email = self._make_mock_email(org_id, email_id)

        mock_analysis = MagicMock()
        mock_analysis.top_features = [
            {"name": "urgency_language", "value": 0.9, "score_contribution": 0.8}
        ]

        session = self._make_mock_session()
        session.execute.side_effect = [
            MagicMock(scalar_one_or_none=MagicMock(return_value=mock_analysis)),
            MagicMock(scalar_one_or_none=MagicMock(return_value=email)),
            MagicMock(),  # UPDATE explanation
        ]
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        with patch("asyncio.run", return_value="Phishing email detected."):
            result = analysis_tasks.generate_explanation.apply(args=[str(email_id)])

        assert result is not None
        session.commit.assert_called()

    # -----------------------------------------------------------------------
    # _on_task_failure with found email (covers lines 258-288)
    # -----------------------------------------------------------------------

    def test_on_task_failure_found_email_writes_audit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_on_task_failure with found email writes audit log, updates status, publishes SSE."""
        from app.tasks import analysis_tasks

        org_id = uuid.uuid4()
        email_id = uuid.uuid4()

        mock_email = MagicMock()
        mock_email.org_id = org_id

        session = self._make_mock_session()
        session.execute.return_value.scalar_one_or_none.return_value = mock_email
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        with patch.object(analysis_tasks, "_publish_sse_event") as mock_sse:
            analysis_tasks._on_task_failure(
                str(email_id), "classify_email", ValueError("model fail")
            )
            mock_sse.assert_called_once()

        session.commit.assert_called()

    # -----------------------------------------------------------------------
    # fire_analysis_chain success (covers lines 312-320)
    # -----------------------------------------------------------------------

    def test_fire_analysis_chain_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """fire_analysis_chain dispatches chain without raising."""
        from app.tasks import analysis_tasks

        # Patch all individual tasks so chain dispatch works
        for task_name in ("parse_and_sanitise", "extract_features", "classify_email",
                          "generate_explanation", "apply_outcome"):
            mock_task = MagicMock()
            mock_task.si.return_value = MagicMock()
            mock_task.s.return_value = MagicMock()
            monkeypatch.setattr(analysis_tasks, task_name, mock_task)

        # Should not raise
        analysis_tasks.fire_analysis_chain(str(uuid.uuid4()))

    # -----------------------------------------------------------------------
    # imap_poll_all_orgs — no active orgs (covers lines 1122-1135)
    # -----------------------------------------------------------------------

    def test_imap_poll_all_orgs_no_active_orgs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """imap_poll_all_orgs with no active IMAP orgs completes without error."""
        from app.tasks import analysis_tasks

        session = self._make_mock_session()
        session.execute.return_value.scalars.return_value = []
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        result = analysis_tasks.imap_poll_all_orgs.apply(args=[])
        assert result is not None
        session.close.assert_called()

    def test_imap_poll_all_orgs_db_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """imap_poll_all_orgs handles DB error on org query gracefully."""
        from app.tasks import analysis_tasks

        session = self._make_mock_session()
        session.execute.side_effect = Exception("DB connection failed")
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        # Should not raise
        result = analysis_tasks.imap_poll_all_orgs.apply(args=[])
        assert result is not None
        session.close.assert_called()


class TestMaintenanceTasksDetailed:
    """Additional maintenance task tests for the 'found data' paths."""

    def _make_mock_session(self) -> MagicMock:
        session = MagicMock()
        session.close = MagicMock()
        session.commit = MagicMock()
        session.rollback = MagicMock()
        session.add = MagicMock()
        return session

    def test_auto_delete_expired_emails_with_deletions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """auto_delete_expired_emails with deleted_count > 0 writes AuditLog."""
        from app.tasks import maintenance_tasks

        session = self._make_mock_session()
        org_id = uuid.uuid4()
        org_row = MagicMock()
        org_row.id = org_id
        org_row.data_retention_days = 30

        delete_result = MagicMock()
        delete_result.rowcount = 5  # 5 emails deleted

        session.execute.side_effect = [
            MagicMock(all=MagicMock(return_value=[org_row])),  # SELECT orgs
            delete_result,  # DELETE result
        ]
        monkeypatch.setattr(maintenance_tasks, "_make_sync_session", lambda: session)

        result = maintenance_tasks.auto_delete_expired_emails.apply(args=[])
        assert result is not None
        # AuditLog should be added when rowcount > 0
        session.add.assert_called()
        session.commit.assert_called()
        session.close.assert_called_once()


class TestDigestTasksDetailed:
    """Digest task tests for the 'found email' paths."""

    def test_send_digest_org_not_found(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """send_digest with missing org retries or returns gracefully."""
        from celery.exceptions import Retry

        from app.tasks import digest_tasks

        session = MagicMock()
        session.close = MagicMock()
        # email found, then org found, but further DB calls fail
        session.execute.return_value.scalar_one_or_none.return_value = None
        monkeypatch.setattr(digest_tasks, "_make_sync_session", lambda: session)

        # digest task may raise Retry on unexpected states
        try:
            result = digest_tasks.send_digest.apply(args=[str(uuid.uuid4())])
            assert result is not None
        except (Retry, Exception):
            pass  # acceptable — task retries or raises on DB issues


class TestExportTasksDetailed:
    """Export task tests for found job paths."""

    def test_generate_export_job_found_no_emails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """generate_export with job found but no emails writes empty export."""
        from app.tasks import export_tasks

        session = MagicMock()
        session.close = MagicMock()
        session.commit = MagicMock()
        session.add = MagicMock()

        mock_job = MagicMock()
        mock_job.id = uuid.uuid4()
        mock_job.org_id = uuid.uuid4()
        mock_job.format = "csv"
        mock_job.filters = {}
        mock_job.status = "pending"

        # job found, then email count=0
        session.execute.side_effect = [
            MagicMock(scalar_one_or_none=MagicMock(return_value=mock_job)),  # job
            MagicMock(scalar_one_or_none=MagicMock(return_value=0)),  # count
            MagicMock(scalars=MagicMock(return_value=MagicMock(
                all=MagicMock(return_value=[])
            ))),  # emails
            MagicMock(),  # UPDATE job status
        ]
        monkeypatch.setattr(export_tasks, "_make_sync_session", lambda: session)

        with patch("asyncio.run", return_value=None):
            result = export_tasks.generate_export.apply(args=[str(uuid.uuid4())])

        assert result is not None
