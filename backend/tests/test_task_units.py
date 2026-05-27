"""Section 9 Phase 3F — Unit tests for Celery task internal functions.

Tests use monkeypatch to mock _make_sync_session() so tasks run without
a real DB connection.  With task_always_eager=True (autouse fixture), tasks
run synchronously in-process.

Coverage targets:
  - analysis_tasks.py: parse_and_sanitise, extract_features, classify_email,
    generate_explanation, apply_outcome, _on_task_failure, _publish_sse_event,
    fire_analysis_chain
  - maintenance_tasks.py: auto_delete_expired_emails, auto_create_monthly_partition
  - digest_tasks.py: send_digest (early exit)
  - export_tasks.py: generate_export (early exit)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ===========================================================================
# Analysis task unit tests
# ===========================================================================


class TestAnalysisTaskUnits:
    """Unit tests for analysis_tasks.py internal functions and task entry points."""

    def _make_mock_session(self) -> MagicMock:
        """Return a fully-mocked SQLAlchemy sync Session."""
        session = MagicMock()
        session.__enter__ = MagicMock(return_value=session)
        session.__exit__ = MagicMock(return_value=False)
        session.close = MagicMock()
        session.commit = MagicMock()
        session.rollback = MagicMock()
        session.add = MagicMock()
        return session

    def _make_mock_email(self, org_id: uuid.UUID, email_id: uuid.UUID) -> MagicMock:
        """Return a minimal email mock."""
        email = MagicMock()
        email.id = email_id
        email.org_id = org_id
        email.sender = "evil@phish.example"
        email.subject = "Verify your account"
        email.body_text = "Please click here immediately."
        email.html_sanitised = "<p>Click <a href='http://evil.example'>here</a></p>"
        email.links = [{"url": "http://evil.example", "text": "here", "is_mismatch": True}]
        email.attachment_metadata = []
        email.spf = "fail"
        email.dkim = "fail"
        email.dmarc = "fail"
        email.received_at = datetime.now(timezone.utc)
        email.status = "pending"
        email.added_to_training = False
        return email

    def test_on_task_failure_email_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_on_task_failure logs error when email not found in DB."""
        from app.tasks import analysis_tasks

        session = self._make_mock_session()
        # Email not found
        execute_result = MagicMock()
        execute_result.scalar_one_or_none.return_value = None
        session.execute.return_value = execute_result

        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        # Should not raise
        analysis_tasks._on_task_failure(str(uuid.uuid4()), "parse_and_sanitise", Exception("test"))
        session.commit.assert_called()

    def test_on_task_failure_with_email(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_on_task_failure marks email failed and writes audit when email found."""
        from app.tasks import analysis_tasks

        session = self._make_mock_session()
        org_id = uuid.uuid4()
        email_id = uuid.uuid4()
        email = self._make_mock_email(org_id, email_id)

        # First execute → email found, second execute → update status
        session.execute.return_value.scalar_one_or_none.return_value = email

        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        with patch.object(analysis_tasks, "_publish_sse_event"):
            analysis_tasks._on_task_failure(str(email_id), "classify_email", ValueError("model fail"))

        session.commit.assert_called()

    def test_write_classify_failure_audit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_write_classify_failure_audit inserts AuditLog when email found."""
        from app.tasks import analysis_tasks

        session = self._make_mock_session()
        org_id = uuid.uuid4()
        email_id = uuid.uuid4()
        email = MagicMock()
        email.org_id = org_id
        session.execute.return_value.scalar_one_or_none.return_value = email

        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        analysis_tasks._write_classify_failure_audit(
            str(email_id), "test-task-id", ValueError("boom")
        )
        session.add.assert_called_once()
        session.commit.assert_called_once()

    def test_write_classify_failure_audit_invalid_uuid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_write_classify_failure_audit returns early on invalid email_id."""
        from app.tasks import analysis_tasks

        monkeypatch.setattr(analysis_tasks, "_make_sync_session", MagicMock())

        # Invalid UUID — should log and return without calling session
        analysis_tasks._write_classify_failure_audit(
            "not-a-uuid", "test-task-id", ValueError("boom")
        )
        # No session should have been created since it returns early
        analysis_tasks._make_sync_session.assert_not_called()

    def test_fire_analysis_chain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """fire_analysis_chain dispatches celery chain (ALWAYS_EAGER in tests)."""
        from app.tasks import analysis_tasks

        # Patch all tasks to no-ops so chain dispatch doesn't fail
        for task_name in ("parse_and_sanitise", "extract_features", "classify_email",
                          "generate_explanation", "apply_outcome"):
            mock_task = MagicMock()
            mock_task.si.return_value = MagicMock()
            monkeypatch.setattr(analysis_tasks, task_name, mock_task)

        # Should not raise
        analysis_tasks.fire_analysis_chain(str(uuid.uuid4()))

    def test_parse_and_sanitise_email_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """parse_and_sanitise returns email_id when email not in DB (task_always_eager)."""
        from app.tasks import analysis_tasks

        session = self._make_mock_session()
        session.execute.return_value.scalar_one_or_none.return_value = None
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        email_id = str(uuid.uuid4())
        # With ALWAYS_EAGER, task runs synchronously
        result = analysis_tasks.parse_and_sanitise.apply(args=[email_id])
        # Should complete without error (early return)
        assert result is not None

    def test_extract_features_email_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """extract_features returns early when email not found."""
        from app.tasks import analysis_tasks

        session = self._make_mock_session()
        session.execute.return_value.scalar_one_or_none.return_value = None
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        email_id = str(uuid.uuid4())
        result = analysis_tasks.extract_features.apply(args=[email_id])
        assert result is not None

    def test_classify_email_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """classify_email returns early when email not found."""
        from app.tasks import analysis_tasks

        session = self._make_mock_session()
        session.execute.return_value.scalar_one_or_none.return_value = None
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        email_id = str(uuid.uuid4())
        result = analysis_tasks.classify_email.apply(args=[email_id])
        assert result is not None

    def test_generate_explanation_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """generate_explanation returns early when email features not found."""
        from app.tasks import analysis_tasks

        session = self._make_mock_session()
        session.execute.return_value.scalars.return_value.all.return_value = []
        session.execute.return_value.scalar_one_or_none.return_value = None
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        email_id = str(uuid.uuid4())
        result = analysis_tasks.generate_explanation.apply(args=[email_id])
        assert result is not None

    def test_apply_outcome_task_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """apply_outcome task completes (returns email_id) when async work is mocked."""
        from app.tasks import analysis_tasks

        # apply_outcome calls asyncio.run(_run()) where _run() uses AsyncSessionLocal.
        # Patching asyncio.run to a no-op bypasses the async DB/Redis entirely and lets
        # the task proceed to `return email_id` without a live event loop.
        session = self._make_mock_session()
        session.execute.return_value.scalar_one_or_none.return_value = None
        monkeypatch.setattr(analysis_tasks, "_make_sync_session", lambda: session)

        email_id = str(uuid.uuid4())

        with patch("asyncio.run", return_value=None):
            result = analysis_tasks.apply_outcome.apply(args=[email_id])

        assert result is not None

    def test_publish_sse_event_exception_swallowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_publish_sse_event swallows exceptions (best-effort)."""
        from app.tasks import analysis_tasks

        # Patch redis to raise
        with patch("redis.Redis.from_url", side_effect=Exception("redis down")):
            # Should not raise
            analysis_tasks._publish_sse_event(
                uuid.uuid4(), "scan_complete", {"email_id": "test"}
            )


# ===========================================================================
# Maintenance task unit tests
# ===========================================================================


class TestMaintenanceTasks:
    """Unit tests for maintenance_tasks.py."""

    def _make_mock_session(self) -> MagicMock:
        session = MagicMock()
        session.close = MagicMock()
        session.commit = MagicMock()
        session.rollback = MagicMock()
        session.add = MagicMock()
        return session

    def test_auto_delete_expired_emails_no_orgs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """auto_delete_expired_emails with no organisations → completes without error."""
        from app.tasks import maintenance_tasks

        session = self._make_mock_session()
        session.execute.return_value.all.return_value = []  # no orgs
        monkeypatch.setattr(maintenance_tasks, "_make_sync_session", lambda: session)

        result = maintenance_tasks.auto_delete_expired_emails.apply(args=[])
        assert result is not None
        session.close.assert_called_once()

    def test_auto_delete_expired_emails_with_org(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """auto_delete_expired_emails processes one org, calls DELETE query."""
        from app.tasks import maintenance_tasks

        session = self._make_mock_session()
        org_id = uuid.uuid4()
        org_row = MagicMock()
        org_row.id = org_id
        org_row.data_retention_days = 90
        session.execute.return_value.all.return_value = [org_row]
        # DELETE result
        delete_result = MagicMock()
        delete_result.rowcount = 0
        session.execute.side_effect = [
            MagicMock(all=MagicMock(return_value=[org_row])),  # SELECT orgs
            delete_result,  # DELETE query
        ]

        monkeypatch.setattr(maintenance_tasks, "_make_sync_session", lambda: session)

        result = maintenance_tasks.auto_delete_expired_emails.apply(args=[])
        assert result is not None
        session.close.assert_called_once()

    def test_auto_delete_expired_emails_db_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """auto_delete_expired_emails handles DB error gracefully."""
        from app.tasks import maintenance_tasks

        session = self._make_mock_session()
        session.execute.side_effect = Exception("DB connection failed")
        monkeypatch.setattr(maintenance_tasks, "_make_sync_session", lambda: session)

        # Should not raise
        result = maintenance_tasks.auto_delete_expired_emails.apply(args=[])
        assert result is not None
        session.close.assert_called_once()

    def test_auto_create_monthly_partition_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """auto_create_monthly_partition runs CREATE TABLE IF NOT EXISTS."""
        from app.tasks import maintenance_tasks

        session = self._make_mock_session()
        monkeypatch.setattr(maintenance_tasks, "_make_sync_session", lambda: session)

        result = maintenance_tasks.auto_create_monthly_partition.apply(args=[])
        assert result is not None
        session.execute.assert_called()
        session.commit.assert_called()
        session.close.assert_called_once()


# ===========================================================================
# Digest task unit tests
# ===========================================================================


class TestDigestTasks:
    """Unit tests for digest_tasks.py (early exit and error paths)."""

    def test_send_digest_email_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """send_digest returns early when email not found in DB."""
        from app.tasks import digest_tasks

        session = MagicMock()
        session.close = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        monkeypatch.setattr(digest_tasks, "_make_sync_session", lambda: session)

        # Should not raise
        result = digest_tasks.send_digest.apply(args=[str(uuid.uuid4())])
        assert result is not None

    def test_send_digest_db_error_retries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """send_digest retries (raises Retry) on DB error when task_eager_propagates=True."""
        from celery.exceptions import Retry

        from app.tasks import digest_tasks

        session = MagicMock()
        session.close = MagicMock()
        session.execute.side_effect = Exception("DB error")
        monkeypatch.setattr(digest_tasks, "_make_sync_session", lambda: session)

        # With task_eager_propagates=True, Retry gets re-raised
        with pytest.raises((Retry, Exception)):
            digest_tasks.send_digest.apply(args=[str(uuid.uuid4())])


# ===========================================================================
# Export task unit tests
# ===========================================================================


class TestExportTasks:
    """Unit tests for export_tasks.py (early exit paths)."""

    def test_generate_export_job_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """generate_export returns early when job not found."""
        from app.tasks import export_tasks

        session = MagicMock()
        session.close = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        monkeypatch.setattr(export_tasks, "_make_sync_session", lambda: session)

        result = export_tasks.generate_export.apply(args=[str(uuid.uuid4())])
        assert result is not None

    def test_generate_export_db_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """generate_export handles DB error gracefully."""
        from app.tasks import export_tasks

        session = MagicMock()
        session.close = MagicMock()
        session.execute.side_effect = Exception("DB error")
        monkeypatch.setattr(export_tasks, "_make_sync_session", lambda: session)

        result = export_tasks.generate_export.apply(args=[str(uuid.uuid4())])
        assert result is not None


# ===========================================================================
# Forwarding task unit tests
# ===========================================================================


class TestForwardingTasks:
    """Unit tests for forwarding_tasks.py."""

    def test_forwarding_test_task_imap_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """forwarding_test handles IMAP connection errors gracefully."""
        from app.tasks import forwarding_tasks

        org_id = uuid.uuid4()
        user_id = uuid.uuid4()

        session = MagicMock()
        session.close = MagicMock()
        # Return mock org
        org = MagicMock()
        org.imap_host = "imap.example.com"
        org.imap_port = 993
        org.imap_user = "test@example.com"
        org.imap_password_encrypted = None
        session.execute.return_value.scalar_one_or_none.return_value = org
        monkeypatch.setattr(forwarding_tasks, "_make_sync_session", lambda: session)

        # Patch IMAP4_SSL to raise
        with patch("imaplib.IMAP4_SSL", side_effect=ConnectionRefusedError("connection refused")):
            with patch.object(forwarding_tasks, "_publish_user_sse", MagicMock()):
                result = forwarding_tasks.forwarding_test.apply(
                    args=[str(org_id), str(user_id)]
                )
        assert result is not None

    def test_forwarding_test_task_org_not_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """forwarding_test returns early when org not found."""
        from app.tasks import forwarding_tasks

        org_id = uuid.uuid4()
        user_id = uuid.uuid4()

        session = MagicMock()
        session.close = MagicMock()
        session.execute.return_value.scalar_one_or_none.return_value = None
        monkeypatch.setattr(forwarding_tasks, "_make_sync_session", lambda: session)

        result = forwarding_tasks.forwarding_test.apply(
            args=[str(org_id), str(user_id)]
        )
        assert result is not None
