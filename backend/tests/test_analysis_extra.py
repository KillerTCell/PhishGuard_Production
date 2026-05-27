"""Section 9 Phase 3F — Additional analysis router tests for coverage.

Covers missed lines in analysis.py:
  - GET /analysis/sample
  - GET /dashboard/insights
  - GET /analysis/stats with period filters and real data
  - GET /analysis/{id}/status 404 case
  - _severity() medium/low branches
"""
from __future__ import annotations

import os
import uuid

os.makedirs("/tmp", exist_ok=True)

from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis_result import AnalysisResult
from app.models.email import Email
from app.models.email_feature import EmailFeature
from app.models.organisation import Organisation
from app.models.user import User
from tests.conftest import EmailFactory


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _make_analysis(
    email_id: uuid.UUID,
    *,
    classification: str = "phishing",
    risk_score: int = 85,
    explanation: str = "Test.",
) -> AnalysisResult:
    return AnalysisResult(
        email_id=email_id,
        classification=classification,
        risk_score=risk_score,
        model_version="rf_test_v1",
        threshold_applied_suspicious=30,
        threshold_applied_phishing=80,
        top_features=[{"name": "urgency_language", "value": 0.8, "score_contribution": 0.8}],
        explanation=explanation,
    )


# ---------------------------------------------------------------------------
# 1. test_get_sample_email
# ---------------------------------------------------------------------------


async def test_get_sample_email(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /analysis/sample → 200 with sender, subject, raw_source."""
    resp = await async_client.get("/api/v1/analysis/sample", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "sender" in data
    assert "subject" in data
    assert "raw_source" in data
    assert len(data["raw_source"]) > 0


# ---------------------------------------------------------------------------
# 2. test_get_dashboard_insights
# ---------------------------------------------------------------------------


async def test_get_dashboard_insights(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /dashboard/insights → 200 list with at least the threshold info insight."""
    resp = await async_client.get("/api/v1/dashboard/insights", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    # Threshold info is always present
    titles = [item["title"] for item in data]
    assert any("threshold" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# 3. test_analysis_status_not_found
# ---------------------------------------------------------------------------


async def test_analysis_status_not_found(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /analysis/{id}/status for unknown id → 404."""
    resp = await async_client.get(
        f"/api/v1/analysis/{uuid.uuid4()}/status",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 4. test_stats_with_real_data_medium_severity
# ---------------------------------------------------------------------------


async def test_stats_with_real_data_medium_severity(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    redis_mock,
) -> None:
    """GET /analysis/stats with suspicious email (medium severity) fills breakdown."""
    # Create quarantined + suspicious emails with analysis
    phishing_email = EmailFactory(org_id=org.id, status="quarantined")
    suspicious_email = EmailFactory(org_id=org.id, status="flagged")
    safe_email = EmailFactory(org_id=org.id, status="delivered")
    db_session.add(phishing_email)
    db_session.add(suspicious_email)
    db_session.add(safe_email)
    await db_session.flush()

    # risk_score=85 → high, risk_score=55 → medium, risk_score=8 → low
    a1 = _make_analysis(phishing_email.id, classification="phishing", risk_score=85)
    a2 = _make_analysis(suspicious_email.id, classification="suspicious", risk_score=55)
    a3 = _make_analysis(safe_email.id, classification="safe", risk_score=8)
    db_session.add(a1)
    db_session.add(a2)
    db_session.add(a3)
    await db_session.flush()

    # Add EmailFeature rows for breakdown
    feat = EmailFeature(
        email_id=phishing_email.id,
        feature_name="urgency_language",
        feature_value=0.9,
        score_contribution=0.8,
    )
    db_session.add(feat)
    await db_session.flush()

    resp = await async_client.get("/api/v1/analysis/stats", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total_analysed"] >= 3
    assert data["quarantined_count"] >= 1
    assert data["safe_count"] >= 1
    assert data["suspicious_count"] >= 1
    assert isinstance(data["detection_driver_breakdown"], list)
    assert isinstance(data["severity_distribution"], dict)
    assert isinstance(data["recent_quarantined"], list)
    # Severity distribution should sum to 100%
    sd = data["severity_distribution"]
    total_pct = sd["critical_pct"] + sd["high_pct"] + sd["medium_pct"] + sd["low_pct"]
    assert abs(total_pct - 100.0) < 1.0, f"Severity pcts should sum to 100, got {total_pct}"


# ---------------------------------------------------------------------------
# 5. test_stats_period_this_week
# ---------------------------------------------------------------------------


async def test_stats_period_this_week(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /analysis/stats?period=this_week → 200 with date-filtered counts."""
    resp = await async_client.get(
        "/api/v1/analysis/stats",
        headers=_auth(admin_token),
        params={"period": "this_week"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "total_analysed" in data
    assert "quarantined_count" in data


# ---------------------------------------------------------------------------
# 6. test_stats_period_30d
# ---------------------------------------------------------------------------


async def test_stats_period_30d(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /analysis/stats?period=30d → 200."""
    resp = await async_client.get(
        "/api/v1/analysis/stats",
        headers=_auth(admin_token),
        params={"period": "30d"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "total_analysed" in data


# ---------------------------------------------------------------------------
# 7. test_analysis_status_pending_no_analysis
# ---------------------------------------------------------------------------


async def test_analysis_status_pending_no_analysis(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    sample_eml: bytes,
) -> None:
    """GET /analysis/{id}/status for pending email → 200, nulls."""
    # Upload creates Email row in pending state
    resp = await async_client.post(
        "/api/v1/emails/upload",
        headers=_auth(admin_token),
        files={"file": ("test.eml", sample_eml, "message/rfc822")},
    )
    assert resp.status_code == 202
    email_id = resp.json()["email_id"]

    status_resp = await async_client.get(
        f"/api/v1/analysis/{email_id}/status",
        headers=_auth(admin_token),
    )
    assert status_resp.status_code == 200, status_resp.text
    data = status_resp.json()
    assert data["status"] in ("pending", "quarantined", "flagged", "delivered", "failed")


# ---------------------------------------------------------------------------
# 8. test_stats_recent_quarantined
# ---------------------------------------------------------------------------


async def test_stats_recent_quarantined(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    redis_mock,
) -> None:
    """GET /analysis/stats recent_quarantined has items when quarantined emails exist."""
    email = EmailFactory(
        org_id=org.id,
        status="quarantined",
        sender="evil@phish.example",
        subject="Your prize awaits",
    )
    db_session.add(email)
    await db_session.flush()
    a = _make_analysis(email.id, risk_score=88)
    db_session.add(a)
    await db_session.flush()

    resp = await async_client.get("/api/v1/analysis/stats", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["recent_quarantined"]) >= 1
    item = data["recent_quarantined"][0]
    assert "id" in item
    assert "risk_score" in item
    assert "severity" in item
