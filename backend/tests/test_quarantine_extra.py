"""Section 9 Phase 3F — Additional quarantine router tests for coverage.

Covers missing lines in quarantine.py:
  - GET /quarantine/{id} with found email (lines 235-291)
  - GET /quarantine/{id}/digest-preview (lines 321-368)
  - GET /quarantine with feedback_state filter (lines 148-159)
  - GET /quarantine with search + sort (lines 147-169)
"""
from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
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
    risk_score: int = 88,
    explanation: str = "Phishing email.",
) -> AnalysisResult:
    return AnalysisResult(
        email_id=email_id,
        classification=classification,
        risk_score=risk_score,
        model_version="rf_test_v1",
        threshold_applied_suspicious=30,
        threshold_applied_phishing=80,
        top_features=[{"name": "urgency_language", "value": 0.9, "score_contribution": 0.8}],
        explanation=explanation,
    )


# ---------------------------------------------------------------------------
# 1. GET /quarantine/{id} — found email (covers lines 235-291)
# ---------------------------------------------------------------------------


async def test_get_quarantine_detail_found(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /quarantine/{id} → 200 with full email detail."""
    email = EmailFactory(
        org_id=org.id,
        status="quarantined",
        sender="attacker@phish.example",
        subject="Urgent: verify now",
        recipient_address="victim@company.example",
    )
    db_session.add(email)
    await db_session.flush()

    analysis = _make_analysis(email.id)
    db_session.add(analysis)

    feat = EmailFeature(
        email_id=email.id,
        feature_name="urgency_language",
        feature_value=0.9,
        score_contribution=0.8,
    )
    db_session.add(feat)
    await db_session.flush()

    resp = await async_client.get(
        f"/api/v1/quarantine/{email.id}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["id"] == str(email.id)
    assert data["risk_score"] == 88
    assert data["classification"] == "phishing"
    assert isinstance(data["top_features"], list)


async def test_get_quarantine_detail_not_in_quarantine(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
) -> None:
    """GET /quarantine/{id} for a delivered email → 404 (not in quarantine)."""
    email = EmailFactory(org_id=org.id, status="delivered")
    db_session.add(email)
    await db_session.flush()

    resp = await async_client.get(
        f"/api/v1/quarantine/{email.id}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 2. GET /quarantine/{id}/digest-preview (covers lines 321-368)
# ---------------------------------------------------------------------------


async def test_get_digest_preview_success(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /quarantine/{id}/digest-preview → 200 with HTML preview."""
    email = EmailFactory(
        org_id=org.id,
        status="quarantined",
        sender="attacker@phish.example",
        subject="Click here now",
        recipient_address="victim@company.example",
        body_text="Please verify your account immediately.",
    )
    db_session.add(email)
    await db_session.flush()

    analysis = _make_analysis(email.id, risk_score=85, explanation="Urgency detected.")
    db_session.add(analysis)

    feat = EmailFeature(
        email_id=email.id,
        feature_name="urgency_language",
        feature_value=0.9,
        score_contribution=0.8,
    )
    db_session.add(feat)
    await db_session.flush()

    resp = await async_client.get(
        f"/api/v1/quarantine/{email.id}/digest-preview",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "html_preview" in data
    assert data["risk_score"] == 85
    assert data["can_send"] is True


async def test_get_digest_preview_no_recipient(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /quarantine/{id}/digest-preview → can_send=False when no recipient."""
    email = EmailFactory(
        org_id=org.id,
        status="quarantined",
        sender="attacker@phish.example",
        subject="Test",
        recipient_address=None,  # no recipient
    )
    db_session.add(email)
    await db_session.flush()

    analysis = _make_analysis(email.id)
    db_session.add(analysis)
    await db_session.flush()

    resp = await async_client.get(
        f"/api/v1/quarantine/{email.id}/digest-preview",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["can_send"] is False


async def test_get_digest_preview_not_found(
    async_client: AsyncClient,
    admin_token: str,
) -> None:
    """GET /quarantine/{id}/digest-preview for unknown id → 404."""
    resp = await async_client.get(
        f"/api/v1/quarantine/{uuid.uuid4()}/digest-preview",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 3. GET /quarantine with feedback_state filter (covers lines 148-159)
# ---------------------------------------------------------------------------


async def test_list_quarantine_feedback_state_filter(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    redis_mock,
) -> None:
    """GET /quarantine?feedback_state=confirmed_phishing applies label filter."""
    resp = await async_client.get(
        "/api/v1/quarantine",
        headers=_auth(admin_token),
        params={"feedback_state": "confirmed_phishing"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "items" in data
    assert "total_count" in data


async def test_list_quarantine_search_filter(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    redis_mock,
) -> None:
    """GET /quarantine?search=phish applies ILIKE filter (covers line 147-149)."""
    email = EmailFactory(
        org_id=org.id,
        status="quarantined",
        sender="phisher@evil.example",
        subject="You've been phished",
    )
    db_session.add(email)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/quarantine",
        headers=_auth(admin_token),
        params={"search": "phish"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total_count"] >= 1


async def test_list_quarantine_sort_by_risk_score(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    redis_mock,
) -> None:
    """GET /quarantine?sort_by=risk_score covers the risk_score sort branch."""
    resp = await async_client.get(
        "/api/v1/quarantine",
        headers=_auth(admin_token),
        params={"sort_by": "risk_score", "sort_dir": "asc"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "items" in data


async def test_list_quarantine_confirmed_phishing_status(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    redis_mock,
) -> None:
    """GET /quarantine includes confirmed_phishing emails (covers mapping logic)."""
    email = EmailFactory(
        org_id=org.id,
        status="confirmed_phishing",
        sender="confirmed@phish.example",
        subject="Confirmed phishing",
    )
    db_session.add(email)
    await db_session.flush()

    analysis = _make_analysis(email.id, classification="phishing", risk_score=95)
    db_session.add(analysis)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/quarantine",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    ids = [item["id"] for item in data["items"]]
    assert str(email.id) in ids
