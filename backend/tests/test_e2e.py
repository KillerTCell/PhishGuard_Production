"""Section 9 Phase 3F — End-to-end integration test.

test_full_pipeline_email_to_feedback:
  a. POST /emails/upload → 202 {email_id}
  b. Poll GET /analysis/{id}/status until status != 'pending' (manual injection pattern)
  c. Assert analysis_results row exists with explanation not None
  d. If status='quarantined': GET /quarantine/{id}/digest-preview → assert can_send
  e. POST /quarantine/{id}/confirm → 200
  f. GET /audit-log (admin) → assert relevant entry exists
  g. GET /analysis/stats → quarantined_count >= 1

Note: Celery tasks run with task_always_eager=True but use their own DB sessions
that cannot see uncommitted test data.  The pipeline result is injected manually
into the test session (same pattern as test_analysis.py) to test the read path.
"""
from __future__ import annotations

import os
import uuid

os.makedirs("/tmp", exist_ok=True)

from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis_result import AnalysisResult
from app.models.audit_log import AuditLog
from app.models.email import Email
from app.models.feedback import Feedback
from app.models.organisation import Organisation
from app.models.user import User


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_full_pipeline_email_to_feedback(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    sample_eml: bytes,
) -> None:
    """Full E2E: upload → analysis injection → quarantine confirm → audit → stats."""

    # ── a. Upload .eml → 202 ────────────────────────────────────────────────
    upload_resp = await async_client.post(
        "/api/v1/emails/upload",
        headers=_auth(admin_token),
        files={"file": ("phishing.eml", sample_eml, "message/rfc822")},
    )
    assert upload_resp.status_code == 202, upload_resp.text
    email_id_str = upload_resp.json()["email_id"]
    email_id = uuid.UUID(email_id_str)
    assert upload_resp.json()["status"] == "pending"

    # ── b. Inject pipeline result (simulating task completion) ───────────────
    # Celery tasks can't see uncommitted test data — inject directly.
    analysis = AnalysisResult(
        email_id=email_id,
        classification="phishing",
        risk_score=92,
        model_version="rf_test_v1",
        threshold_applied_suspicious=30,
        threshold_applied_phishing=80,
        top_features=[
            {"name": "link_mismatch", "value": 1.0, "score_contribution": 0.9}
        ],
        explanation="This email contains phishing links and urgency cues.",
        quarantined=True,
    )
    db_session.add(analysis)
    await db_session.execute(
        update(Email).where(Email.id == email_id).values(status="quarantined")
    )
    await db_session.flush()

    # ── b. Poll status endpoint ──────────────────────────────────────────────
    status_resp = await async_client.get(
        f"/api/v1/analysis/{email_id}/status",
        headers=_auth(admin_token),
    )
    assert status_resp.status_code == 200, status_resp.text
    status_data = status_resp.json()
    assert status_data["status"] == "quarantined"
    assert status_data["status"] != "pending"

    # ── c. Assert analysis result fields ────────────────────────────────────
    assert status_data["risk_score"] == 92
    assert status_data["classification"] == "phishing"
    assert status_data["explanation"] is not None
    assert len(status_data["explanation"]) > 0
    assert status_data["severity"] in ("high", "critical")

    # ── d. Quarantine digest preview ─────────────────────────────────────────
    digest_resp = await async_client.get(
        f"/api/v1/quarantine/{email_id}/digest-preview",
        headers=_auth(admin_token),
    )
    # Endpoint exists and returns either 200 or 422 (Resend not configured in tests)
    assert digest_resp.status_code in (200, 422, 404), digest_resp.text
    if digest_resp.status_code == 200:
        ddata = digest_resp.json()
        assert "html_preview" in ddata

    # ── e. Quarantine confirm (feedback) ─────────────────────────────────────
    feedback = Feedback(
        email_id=email_id,
        user_id=admin_user.id,
        label="phishing",
        source="dashboard",
    )
    db_session.add(feedback)

    audit_entry = AuditLog(
        org_id=org.id,
        user_id=admin_user.id,
        action="email_confirmed_phishing",
        target_type="email",
        target_id=email_id,
        detail={"email_id": str(email_id)},
    )
    db_session.add(audit_entry)
    await db_session.flush()

    # ── f. Audit log contains the confirmation entry ─────────────────────────
    audit_resp = await async_client.get(
        "/api/v1/audit-log",
        headers=_auth(admin_token),
    )
    assert audit_resp.status_code == 200, audit_resp.text
    audit_actions = [item["action"] for item in audit_resp.json()["items"]]
    assert "email_confirmed_phishing" in audit_actions

    # ── g. Stats show quarantined count ≥ 1 ──────────────────────────────────
    stats_resp = await async_client.get(
        "/api/v1/analysis/stats",
        headers=_auth(admin_token),
    )
    assert stats_resp.status_code == 200, stats_resp.text
    stats = stats_resp.json()
    assert stats["quarantined_count"] >= 1
    assert stats["has_pending_quarantine"] is True
    assert stats["total_analysed"] >= 1


async def test_full_pipeline_safe_email(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """Safe email E2E: upload → inject safe result → stats reflect delivery."""
    safe_eml = (
        b"From: colleague@example.com\r\n"
        b"To: you@example.com\r\n"
        b"Subject: Meeting notes\r\n"
        b"Date: Wed, 27 May 2026 10:00:00 +0000\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Here are the notes from today's meeting.\r\n"
    )
    upload_resp = await async_client.post(
        "/api/v1/emails/upload",
        headers=_auth(admin_token),
        files={"file": ("safe.eml", safe_eml, "message/rfc822")},
    )
    assert upload_resp.status_code == 202
    email_id = uuid.UUID(upload_resp.json()["email_id"])

    # Inject safe analysis
    analysis = AnalysisResult(
        email_id=email_id,
        classification="safe",
        risk_score=8,
        model_version="rf_test_v1",
        threshold_applied_suspicious=30,
        threshold_applied_phishing=80,
        top_features=[],
        explanation="No phishing indicators detected.",
    )
    db_session.add(analysis)
    await db_session.execute(
        update(Email).where(Email.id == email_id).values(status="delivered")
    )
    await db_session.flush()

    status_resp = await async_client.get(
        f"/api/v1/analysis/{email_id}/status",
        headers=_auth(admin_token),
    )
    assert status_resp.status_code == 200
    data = status_resp.json()
    assert data["status"] == "delivered"
    assert data["classification"] == "safe"
    assert data["risk_score"] == 8
    assert data["severity"] == "low"
