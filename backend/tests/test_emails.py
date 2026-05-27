"""Section 9 Phase 3F — Email list, detail, and delete endpoint tests.

Covers: GET /emails, GET /emails/{id}, DELETE /emails/{id}
(POST /emails/upload is already tested in test_analysis.py)
"""
from __future__ import annotations

import os
import uuid

os.makedirs("/tmp", exist_ok=True)

import pytest
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
    explanation: str = "Test explanation for phishing email.",
) -> AnalysisResult:
    return AnalysisResult(
        email_id=email_id,
        classification=classification,
        risk_score=risk_score,
        model_version="rf_test_v1",
        threshold_applied_suspicious=30,
        threshold_applied_phishing=80,
        top_features=[
            {"name": "urgency_language", "value": 0.8, "score_contribution": 0.8}
        ],
        explanation=explanation,
    )


# ---------------------------------------------------------------------------
# 1. test_list_emails_empty
# ---------------------------------------------------------------------------


async def test_list_emails_empty(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails with no emails → 200, empty items list."""
    resp = await async_client.get("/api/v1/emails", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0
    assert data["page"] == 1


# ---------------------------------------------------------------------------
# 2. test_list_emails_with_results
# ---------------------------------------------------------------------------


async def test_list_emails_with_results(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails with emails in DB → returns correct items."""
    email = EmailFactory(org_id=org.id, status="quarantined", sender="evil@phish.example", subject="Win now!")
    db_session.add(email)
    await db_session.flush()  # email must exist before analysis FK
    analysis = _make_analysis(email.id, classification="phishing", risk_score=88)
    db_session.add(analysis)
    await db_session.flush()

    resp = await async_client.get("/api/v1/emails", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total"] >= 1
    ids = [item["id"] for item in data["items"]]
    assert str(email.id) in ids


# ---------------------------------------------------------------------------
# 3. test_list_emails_pagination
# ---------------------------------------------------------------------------


async def test_list_emails_pagination(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails?page=1&page_size=2 → pagination metadata correct."""
    for i in range(3):
        e = EmailFactory(org_id=org.id, status="delivered")
        db_session.add(e)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/emails",
        headers=_auth(admin_token),
        params={"page": 1, "page_size": 2},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["items"]) <= 2
    assert data["total"] >= 3
    assert data["pages"] >= 2


# ---------------------------------------------------------------------------
# 4. test_list_emails_status_filter
# ---------------------------------------------------------------------------


async def test_list_emails_status_filter(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails?status=quarantined → only quarantined emails."""
    quarantined = EmailFactory(org_id=org.id, status="quarantined")
    delivered = EmailFactory(org_id=org.id, status="delivered")
    db_session.add(quarantined)
    db_session.add(delivered)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/emails",
        headers=_auth(admin_token),
        params={"status": "quarantined"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    for item in data["items"]:
        assert item["status"] == "quarantined"


# ---------------------------------------------------------------------------
# 5. test_list_emails_risk_band_filter
# ---------------------------------------------------------------------------


async def test_list_emails_risk_band_filter(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails?risk_band=critical → only emails with risk_score >= 90."""
    email_critical = EmailFactory(org_id=org.id, status="quarantined")
    email_low = EmailFactory(org_id=org.id, status="delivered")
    db_session.add(email_critical)
    db_session.add(email_low)
    await db_session.flush()  # flush emails before adding analysis FK rows
    analysis_critical = _make_analysis(email_critical.id, risk_score=95)
    analysis_low = _make_analysis(email_low.id, classification="safe", risk_score=10)
    db_session.add(analysis_critical)
    db_session.add(analysis_low)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/emails",
        headers=_auth(admin_token),
        params={"risk_band": "critical"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    for item in data["items"]:
        assert item["risk_score"] is not None
        assert item["risk_score"] >= 90


# ---------------------------------------------------------------------------
# 6. test_list_emails_search
# ---------------------------------------------------------------------------


async def test_list_emails_search(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails?search=phishy → returns emails matching sender/subject."""
    email = EmailFactory(
        org_id=org.id,
        sender="phishy@evil.example",
        subject="Totally normal email",
        status="flagged",
    )
    other = EmailFactory(org_id=org.id, sender="normal@company.com", status="delivered")
    db_session.add(email)
    db_session.add(other)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/emails",
        headers=_auth(admin_token),
        params={"search": "phishy"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    ids = [item["id"] for item in data["items"]]
    assert str(email.id) in ids
    assert str(other.id) not in ids


# ---------------------------------------------------------------------------
# 7. test_list_emails_sort_by_risk_score
# ---------------------------------------------------------------------------


async def test_list_emails_sort_by_risk_score(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails?sort_by=risk_score&sort_dir=desc → descending risk scores."""
    e1 = EmailFactory(org_id=org.id, status="quarantined")
    e2 = EmailFactory(org_id=org.id, status="flagged")
    db_session.add(e1)
    db_session.add(e2)
    await db_session.flush()  # emails first
    a1 = _make_analysis(e1.id, risk_score=90)
    a2 = _make_analysis(e2.id, classification="suspicious", risk_score=45)
    db_session.add(a1)
    db_session.add(a2)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/emails",
        headers=_auth(admin_token),
        params={"sort_by": "risk_score", "sort_dir": "desc"},
    )
    assert resp.status_code == 200, resp.text
    scores = [item["risk_score"] for item in resp.json()["items"] if item["risk_score"] is not None]
    assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# 8. test_get_email_detail_success
# ---------------------------------------------------------------------------


async def test_get_email_detail_success(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails/{id} → 200 with full detail including analysis."""
    email = EmailFactory(
        org_id=org.id,
        sender="evil@phish.example",
        subject="Verify your account",
        status="quarantined",
        spf="fail",
        dkim="fail",
        dmarc="fail",
    )
    db_session.add(email)
    await db_session.flush()  # email must exist before analysis + feature FKs
    analysis = _make_analysis(email.id, classification="phishing", risk_score=88)
    db_session.add(analysis)

    feature = EmailFeature(
        email_id=email.id,
        feature_name="urgency_language",
        feature_value=0.9,
        score_contribution=0.7,
    )
    db_session.add(feature)
    await db_session.flush()

    resp = await async_client.get(
        f"/api/v1/emails/{email.id}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["id"] == str(email.id)
    assert data["sender"] == "evil@phish.example"
    assert data["risk_score"] == 88
    assert data["classification"] == "phishing"
    assert data["explanation"] == "Test explanation for phishing email."
    assert data["severity"] in ("high", "critical")
    assert len(data["top_features"]) >= 1


# ---------------------------------------------------------------------------
# 9. test_get_email_detail_not_found
# ---------------------------------------------------------------------------


async def test_get_email_detail_not_found(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails/{nonexistent_id} → 404."""
    resp = await async_client.get(
        f"/api/v1/emails/{uuid.uuid4()}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 404, resp.text


# ---------------------------------------------------------------------------
# 10. test_get_email_detail_pending_no_analysis
# ---------------------------------------------------------------------------


async def test_get_email_detail_pending_no_analysis(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails/{id} for pending email (no AnalysisResult yet) → 200, nulls."""
    email = EmailFactory(org_id=org.id, status="pending")
    db_session.add(email)
    await db_session.flush()

    resp = await async_client.get(
        f"/api/v1/emails/{email.id}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["risk_score"] is None
    assert data["classification"] is None
    assert data["status"] == "pending"


# ---------------------------------------------------------------------------
# 11. test_delete_email_admin_success
# ---------------------------------------------------------------------------


async def test_delete_email_admin_success(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """DELETE /emails/{id} (admin) → 204, email gone."""
    email = EmailFactory(org_id=org.id, status="quarantined")
    db_session.add(email)
    await db_session.flush()

    resp = await async_client.delete(
        f"/api/v1/emails/{email.id}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 204, resp.text

    # Verify gone
    get_resp = await async_client.get(
        f"/api/v1/emails/{email.id}",
        headers=_auth(admin_token),
    )
    assert get_resp.status_code == 404


# ---------------------------------------------------------------------------
# 12. test_delete_email_not_found
# ---------------------------------------------------------------------------


async def test_delete_email_not_found(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """DELETE /emails/{nonexistent_id} → 404."""
    resp = await async_client.delete(
        f"/api/v1/emails/{uuid.uuid4()}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 13. test_delete_email_analyst_forbidden
# ---------------------------------------------------------------------------


async def test_delete_email_analyst_forbidden(
    async_client: AsyncClient,
    analyst_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    analyst_user: User,
) -> None:
    """DELETE /emails/{id} with analyst token → 403."""
    email = EmailFactory(org_id=org.id, status="quarantined")
    db_session.add(email)
    await db_session.flush()

    resp = await async_client.delete(
        f"/api/v1/emails/{email.id}",
        headers=_auth(analyst_token),
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 14. test_upload_eml_unauthenticated
# ---------------------------------------------------------------------------


async def test_upload_eml_unauthenticated(
    async_client: AsyncClient,
    sample_eml: bytes,
) -> None:
    """POST /emails/upload without auth token → 401."""
    resp = await async_client.post(
        "/api/v1/emails/upload",
        files={"file": ("test.eml", sample_eml, "message/rfc822")},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 15. test_list_emails_risk_band_high
# ---------------------------------------------------------------------------


async def test_list_emails_risk_band_high(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails?risk_band=high → only 80 <= risk_score < 90."""
    email = EmailFactory(org_id=org.id, status="quarantined")
    db_session.add(email)
    await db_session.flush()
    analysis = _make_analysis(email.id, risk_score=85)
    db_session.add(analysis)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/emails",
        headers=_auth(admin_token),
        params={"risk_band": "high"},
    )
    assert resp.status_code == 200
    data = resp.json()
    for item in data["items"]:
        assert 80 <= item["risk_score"] < 90


# ---------------------------------------------------------------------------
# 16. test_list_emails_risk_band_medium
# ---------------------------------------------------------------------------


async def test_list_emails_risk_band_medium(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails?risk_band=medium → only 30 <= risk_score < 80."""
    email = EmailFactory(org_id=org.id, status="flagged")
    db_session.add(email)
    await db_session.flush()
    analysis = _make_analysis(email.id, classification="suspicious", risk_score=55)
    db_session.add(analysis)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/emails",
        headers=_auth(admin_token),
        params={"risk_band": "medium"},
    )
    assert resp.status_code == 200
    data = resp.json()
    for item in data["items"]:
        assert 30 <= item["risk_score"] < 80


# ---------------------------------------------------------------------------
# 17. test_list_emails_risk_band_low
# ---------------------------------------------------------------------------


async def test_list_emails_risk_band_low(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /emails?risk_band=low → only risk_score < 30."""
    email = EmailFactory(org_id=org.id, status="delivered")
    db_session.add(email)
    await db_session.flush()
    analysis = _make_analysis(email.id, classification="safe", risk_score=5)
    db_session.add(analysis)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/emails",
        headers=_auth(admin_token),
        params={"risk_band": "low"},
    )
    assert resp.status_code == 200
    data = resp.json()
    for item in data["items"]:
        assert item["risk_score"] < 30
