"""Section 9 Phase 3F — Load and performance tests (N-01, N-02).

Tests:
  test_upload_rate_under_10s  — 10 uploads with ALWAYS_EAGER tasks, total < 10s
  test_dashboard_stats_under_2s — GET /analysis/stats with records, < 2s

Manual locust run (NOT run automatically):
  locust -f tests/test_load.py --headless -u 100 -r 10 --run-time 60s
"""
from __future__ import annotations

import os
import time
import uuid

os.makedirs("/tmp", exist_ok=True)

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis_result import AnalysisResult
from app.models.organisation import Organisation
from app.models.user import User
from tests.conftest import EmailFactory

_PHISHING_EML = (
    b"From: security-alert@paypa1-secure.com\r\n"
    b"To: victim@example.com\r\n"
    b"Subject: Urgent: Your account has been suspended\r\n"
    b"Date: Wed, 27 May 2026 09:00:00 +0000\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<html><body><p>Your account has been <strong>suspended</strong>.</p>"
    b"<p>Click <a href='http://paypa1-secure.com/login'>here</a> now.</p></body></html>\r\n"
)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# N-01: Upload rate test
# ---------------------------------------------------------------------------


@pytest.mark.slow
async def test_upload_rate_under_10s(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """10 uploads with ALWAYS_EAGER Celery tasks complete in under 10 seconds.

    This verifies that the upload endpoint + task dispatch overhead is
    acceptable under sequential single-user load (N-01 requirement).
    Celery tasks are eager (synchronous) so this includes full chain execution.
    """
    start = time.perf_counter()
    successes = 0

    for i in range(10):
        resp = await async_client.post(
            "/api/v1/emails/upload",
            headers=_auth(admin_token),
            files={"file": (f"test_{i}.eml", _PHISHING_EML, "message/rfc822")},
        )
        if resp.status_code == 202:
            successes += 1

    elapsed = time.perf_counter() - start

    assert successes == 10, f"Only {successes}/10 uploads succeeded"
    assert elapsed < 10.0, (
        f"10 uploads took {elapsed:.2f}s — expected < 10s (N-01)"
    )


# ---------------------------------------------------------------------------
# N-02: Dashboard stats response time
# ---------------------------------------------------------------------------


@pytest.mark.slow
async def test_dashboard_stats_under_2s(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /analysis/stats with 50 email records responds in under 2 seconds (N-02).

    Full 1000-record seed is impractical in a unit test; 50 records gives a
    representative DB read with realistic JOIN overhead.
    """
    # Seed 50 email records with varied statuses
    statuses = ["quarantined", "flagged", "delivered", "failed", "pending"]
    emails = []
    for i in range(50):
        email = EmailFactory(org_id=org.id, status=statuses[i % len(statuses)])
        db_session.add(email)
        emails.append((i, email))
    await db_session.flush()  # flush all emails first (FK constraint)
    for i, email in emails:
        if i % 5 == 0:
            analysis = AnalysisResult(
                email_id=email.id,
                classification="phishing",
                risk_score=85,
                model_version="rf_test",
                threshold_applied_suspicious=30,
                threshold_applied_phishing=80,
                top_features=[],
                explanation="Test.",
            )
            db_session.add(analysis)
    await db_session.flush()

    start = time.perf_counter()
    resp = await async_client.get("/api/v1/analysis/stats", headers=_auth(admin_token))
    elapsed = time.perf_counter() - start

    assert resp.status_code == 200, resp.text
    assert elapsed < 2.0, (
        f"/analysis/stats took {elapsed:.3f}s with 50 records — expected < 2s (N-02)"
    )
    data = resp.json()
    assert "total_analysed" in data
    assert "quarantined_count" in data
