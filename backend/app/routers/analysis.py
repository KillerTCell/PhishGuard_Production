"""Section 4.3 -- FR-03, FR-04, Dashboard: Analysis and stats endpoints.

POST /analysis/paste         -- paste raw email source (S-03: max_length=500000)
POST /analysis/public-check  -- unauthenticated quick check (rate-limited 10/min)
GET  /analysis/sample        -- load demo .eml for 'Load Sample' button (public)
GET  /analysis/{id}/status   -- lightweight polling fallback before SSE
GET  /analysis/stats         -- dashboard cards + charts (A-09, A-12 fixes)
GET  /dashboard/insights     -- AI insights panel (Redis cache 60 s)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import redis.asyncio as aioredis
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.core.limiter import limiter
from app.dependencies import CurrentUser, get_current_user, get_db, get_redis
from app.models.analysis_result import AnalysisResult
from app.models.email import Email
from app.models.email_feature import EmailFeature
from app.models.feedback import Feedback
from app.models.organisation import Organisation
from app.schemas.analysis import (
    AnalysisStatsResponse,
    AnalysisStatusResponse,
    CurrentThreshold,
    DetectionDriverItem,
    InsightItem,
    PasteAnalysisRequest,
    PasteAnalysisResponse,
    PublicCheckRequest,
    PublicCheckResponse,
    PublicCheckTopFeature,
    RecentQuarantinedItem,
    SampleEmailResponse,
    SeverityDistribution,
)
from app.schemas.common import Severity, StatsPeriod, score_to_severity

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["analysis"])

_STATS_CACHE_TTL = 30   # seconds per Section 4.3

# Feature name ordering for breakdown chart (Section 5.1)
_FEATURE_NAMES = [
    "urgency_language",
    "credential_request",
    "impersonation_language",
    "grammar_quality",
    "link_mismatch",
    "auth_failure",
    "known_bad_url",
]


def _severity(risk_score: int | None) -> Severity | None:
    """Derive the 5-band severity from risk score (0-100).

    ``severity`` is not a DB column on AnalysisResult — it is computed at
    read time from ``risk_score``.

    Args:
        risk_score: Integer 0-100, or ``None`` when analysis is pending.

    Returns:
        One of the five :class:`~app.schemas.common.Severity` bands;
        ``None`` when *risk_score* is ``None``.
    """
    if risk_score is None:
        return None
    return score_to_severity(risk_score)


# ---------------------------------------------------------------------------
# POST /analysis/paste
# ---------------------------------------------------------------------------


@router.post(
    "/analysis/paste",
    response_model=PasteAnalysisResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit raw email source for analysis",
)
async def paste_analysis(
    body: PasteAnalysisRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> PasteAnalysisResponse:
    """Ingest raw email source text and queue it for the analysis pipeline.

    S-03 fix: max_length=500_000 enforced in PasteAnalysisRequest schema.
    Inserts an Email row with ingestion_source='paste' then fires Celery chain.
    """
    email_id = uuid.uuid4()
    email_record = Email(
        id=email_id,
        org_id=current_user.org_id,
        ingestion_source="paste",
        status="pending",
        received_at=datetime.now(timezone.utc),
        added_to_training=body.add_to_training,
        sender=body.sender,
        subject=body.subject,
        body_text=body.raw_source,
    )
    db.add(email_record)
    await db.flush()

    # Fire the same analysis chain as upload (Section 5.1 Task 1–5)
    try:
        from app.tasks.analysis_tasks import (  # noqa: PLC0415
            apply_outcome,
            classify_email,
            extract_features,
            generate_explanation,
            parse_and_sanitise,
        )

        (
            parse_and_sanitise.si(str(email_id))
            | extract_features.si(str(email_id))
            | classify_email.si(str(email_id))
            | generate_explanation.si(str(email_id))
            | apply_outcome.si(str(email_id))
        ).delay()
    except Exception as exc:
        logger.warning(
            "paste_chain_dispatch_failed",
            email_id=str(email_id),
            error=str(exc),
        )

    return PasteAnalysisResponse(email_id=email_id, status="pending")


# ---------------------------------------------------------------------------
# POST /analysis/public-check  (unauthenticated, rate-limited)
# ---------------------------------------------------------------------------

_PUBLIC_FEAT_ORDER = [
    "urgency_language",
    "credential_request",
    "link_mismatch",
    "impersonation_language",
    "auth_failure",
    "grammar_quality",
    "known_bad_url",
]

_PUBLIC_FEAT_LABELS: dict[str, str] = {
    "urgency_language":       "uses urgent or threatening language",
    "credential_request":     "requests login credentials or personal data",
    "impersonation_language": "impersonates a known brand or authority",
    "grammar_quality":        "contains poor grammar typical of phishing",
    "link_mismatch":          "contains links where display text doesn't match the URL",
    "auth_failure":           "failed SPF/DKIM/DMARC email authentication",
    "known_bad_url":          "contains URLs from known phishing lists",
}


def _public_explanation(risk_score: int, top: list[dict]) -> str:
    active = [f for f in top if f["score"] > 0]
    if not active:
        return "No strong phishing indicators detected in this email."
    parts = " and ".join(
        _PUBLIC_FEAT_LABELS.get(f["name"], f["name"].replace("_", " ")) for f in active[:2]
    )
    if risk_score >= 70:
        return f"This email is likely phishing: it {parts}."
    if risk_score >= 30:
        return f"This email shows suspicious signs: it {parts}."
    return "This email appears safe — no strong phishing indicators detected."


@router.post(
    "/analysis/public-check",
    response_model=PublicCheckResponse,
    summary="Unauthenticated quick-check — ML only, result not saved",
)
@limiter.limit("10/minute")
async def public_check(
    request: Request,
    body: PublicCheckRequest,
    redis: aioredis.Redis = Depends(get_redis),
) -> PublicCheckResponse:
    """Rate-limited (10/min per IP), no JWT required, no DB write.

    Parses raw_content as .eml if it has RFC 2822 headers; otherwise treats
    it as plain text. Runs the 7-feature NLP pipeline then the ML classifier.
    """
    from app.services.email_parser import parse_eml  # noqa: PLC0415
    from app.services.ml_classifier import ModelNotFoundError, classify  # noqa: PLC0415
    from app.services.nlp_pipeline import extract_all_features  # noqa: PLC0415

    try:
        parsed = parse_eml(body.raw_content.encode("utf-8", errors="replace"))
        email_dict: dict = {
            "body_text": parsed.get("body_text") or body.raw_content,
            "links":     parsed.get("links") or [],
            "spf":       parsed.get("spf") or "none",
            "dkim":      parsed.get("dkim") or "none",
            "dmarc":     parsed.get("dmarc") or "none",
            "sender":    parsed.get("sender") or "",
        }
    except Exception:
        email_dict = {
            "body_text": body.raw_content,
            "links":     [],
            "spf":       "none",
            "dkim":      "none",
            "dmarc":     "none",
            "sender":    "",
        }

    features = await extract_all_features(email_dict, redis)
    feat_map = {f.feature_name: f.score_contribution for f in features}
    feature_vector = [feat_map.get(name, 0.0) for name in _PUBLIC_FEAT_ORDER]

    try:
        clf = classify(feature_vector)
    except ModelNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML model not ready — please try again shortly.",
        )

    risk_score: int = clf["risk_score"]
    risk_label: str = clf["severity"]

    top_features = sorted(
        [{"name": f.feature_name, "score": f.score_contribution} for f in features],
        key=lambda x: x["score"],
        reverse=True,
    )[:3]

    explanation = _public_explanation(risk_score, top_features)

    logger.info(
        "public_check_complete",
        risk_score=risk_score,
        risk_label=risk_label,
        ip=request.client.host if request.client else "unknown",
    )

    return PublicCheckResponse(
        risk_score=risk_score,
        risk_label=risk_label,
        explanation=explanation,
        top_features=[PublicCheckTopFeature(**f) for f in top_features],
    )


# ---------------------------------------------------------------------------
# GET /analysis/sample
# ---------------------------------------------------------------------------


@router.get(
    "/analysis/sample",
    response_model=SampleEmailResponse,
    summary="Load demo phishing sample for 'Load Sample' button",
)
async def get_sample() -> SampleEmailResponse:
    """Return a hardcoded realistic phishing sample from DEMO_SAMPLE_EML config.

    Public endpoint — no auth required. Used by the Quick Check 'Load sample'
    button and the authenticated Paste Analysis page.
    """
    sample_path = app_settings.DEMO_SAMPLE_EML
    if sample_path:
        try:
            with open(sample_path, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            return SampleEmailResponse(
                sender="security-alert@paypa1-secure.com",
                subject="Urgent: Verify your PayPal account immediately",
                raw_source=raw,
            )
        except OSError:
            pass

    # Fallback built-in sample
    raw_source = (
        "From: security-alert@paypa1-secure.com\r\n"
        "To: victim@example.com\r\n"
        "Subject: Urgent: Verify your PayPal account immediately\r\n"
        "Date: Mon, 25 May 2026 08:00:00 +0000\r\n"
        "\r\n"
        "Dear Customer,\r\n\r\n"
        "Your PayPal account has been temporarily limited due to unauthorized access.\r\n"
        "Please verify your account immediately by clicking the link below:\r\n\r\n"
        "http://paypa1-secure.com/verify?token=abc123\r\n\r\n"
        "Failure to verify within 24 hours will result in account suspension.\r\n\r\n"
        "PayPal Security Team"
    )
    return SampleEmailResponse(
        sender="security-alert@paypa1-secure.com",
        subject="Urgent: Verify your PayPal account immediately",
        raw_source=raw_source,
    )


# ---------------------------------------------------------------------------
# GET /analysis/{id}/status
# ---------------------------------------------------------------------------


@router.get(
    "/analysis/{email_id}/status",
    response_model=AnalysisStatusResponse,
    summary="Poll analysis status (fallback before SSE connects)",
)
async def get_analysis_status(
    email_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AnalysisStatusResponse:
    """Return the current analysis status for a single email.

    Lightweight polling endpoint used by the frontend progress bar before
    the SSE connection is established.  org_id filter enforced.
    """
    result = await db.execute(
        select(Email, AnalysisResult)
        .outerjoin(AnalysisResult, AnalysisResult.email_id == Email.id)
        .where(Email.id == email_id, Email.org_id == current_user.org_id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    email, analysis = row
    return AnalysisStatusResponse(
        status=email.status,
        risk_score=analysis.risk_score if analysis else None,
        classification=analysis.classification if analysis else None,
        severity=_severity(analysis.risk_score if analysis else None),
        explanation=analysis.explanation if analysis else None,
    )


# ---------------------------------------------------------------------------
# GET /analysis/stats
# ---------------------------------------------------------------------------


@router.get(
    "/analysis/stats",
    response_model=AnalysisStatsResponse,
    summary="Dashboard stats (all cards + charts)",
)
async def get_analysis_stats(
    period: StatsPeriod = StatsPeriod.all_time,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> AnalysisStatsResponse:
    """Return comprehensive dashboard statistics.

    Redis cache per (org_id, period), TTL 30 s.
    Cache is invalidated on scan_complete SSE event (done in analysis_tasks).

    A-09 fix: recent_quarantined includes severity + top_reason.
    A-12 fix: has_pending_quarantine drives 'Prepare Digest' button state.
    """
    cache_key = f"stats:{current_user.org_id}:{period.value}"
    cached = await redis.get(cache_key)
    if cached:
        return AnalysisStatsResponse(**json.loads(cached))

    org_id = current_user.org_id
    now = datetime.now(timezone.utc)

    # Date filter
    if period == StatsPeriod.this_week:
        since = now - timedelta(days=7)
    elif period == StatsPeriod.days_30:
        since = now - timedelta(days=30)
    else:
        since = None

    email_base = select(Email).where(Email.org_id == org_id)
    if since:
        email_base = email_base.where(Email.received_at >= since)

    # Counts
    total_analysed: int = (
        await db.execute(select(func.count()).select_from(email_base.subquery()))
    ).scalar_one()

    safe_count: int = (
        await db.execute(
            select(func.count()).select_from(
                email_base.where(
                    Email.id.in_(
                        select(AnalysisResult.email_id).where(AnalysisResult.classification == "safe")
                    )
                ).subquery()
            )
        )
    ).scalar_one()

    suspicious_count: int = (
        await db.execute(
            select(func.count()).select_from(
                email_base.where(
                    Email.id.in_(
                        select(AnalysisResult.email_id).where(AnalysisResult.classification == "suspicious")
                    )
                ).subquery()
            )
        )
    ).scalar_one()

    quarantined_count: int = (
        await db.execute(
            select(func.count()).select_from(
                email_base.where(Email.status == "quarantined").subquery()
            )
        )
    ).scalar_one()

    feedback_count: int = (
        await db.execute(
            select(func.count(Feedback.id)).join(Email, Email.id == Feedback.email_id).where(
                Email.org_id == org_id
            )
        )
    ).scalar_one()

    # Org thresholds
    org = (await db.execute(select(Organisation).where(Organisation.id == org_id))).scalar_one()
    threshold = CurrentThreshold(
        suspicious=org.suspicious_threshold,
        phishing=org.phishing_threshold,
    )

    # Detection driver breakdown (feature usage counts)
    feature_rows = (
        await db.execute(
            select(EmailFeature.feature_name, func.count(EmailFeature.id).label("cnt"))
            .join(Email, Email.id == EmailFeature.email_id)
            .where(Email.org_id == org_id)
            .where(EmailFeature.score_contribution > 0)
            .group_by(EmailFeature.feature_name)
        )
    ).all()

    feature_total = sum(r.cnt for r in feature_rows) or 1
    detection_breakdown = [
        DetectionDriverItem(
            feature_name=r.feature_name,
            count=r.cnt,
            pct=round(r.cnt / feature_total * 100, 1),
        )
        for r in feature_rows
    ]

    # Severity distribution — severity is computed from risk_score (not a DB column)
    risk_score_rows = (
        await db.execute(
            select(AnalysisResult.risk_score)
            .join(Email, Email.id == AnalysisResult.email_id)
            .where(Email.org_id == org_id)
        )
    ).scalars().all()

    # 5-band severity folded into the 4-segment dashboard chart:
    # suspicious → medium_pct, safe+low → low_pct ("Low / Safe" segment).
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "suspicious": 0, "low": 0, "safe": 0}
    for rs in risk_score_rows:
        band = _severity(rs) or Severity.safe
        sev_counts[band.value] += 1

    sev_total = sum(sev_counts.values()) or 1
    severity_dist = SeverityDistribution(
        critical_pct=round(sev_counts["critical"] / sev_total * 100, 1),
        high_pct=round(sev_counts["high"] / sev_total * 100, 1),
        medium_pct=round(sev_counts["suspicious"] / sev_total * 100, 1),
        low_pct=round((sev_counts["low"] + sev_counts["safe"]) / sev_total * 100, 1),
    )

    # Recent quarantined (last 5)
    recent_q_rows = (
        await db.execute(
            select(Email, AnalysisResult)
            .join(AnalysisResult, AnalysisResult.email_id == Email.id)
            .where(Email.org_id == org_id, Email.status.in_(["quarantined", "confirmed_phishing"]))
            .order_by(Email.received_at.desc())
            .limit(5)
        )
    ).all()

    recent_quarantined = [
        RecentQuarantinedItem(
            id=row.Email.id,
            sender=row.Email.sender,
            subject=row.Email.subject,
            risk_score=row.AnalysisResult.risk_score,
            severity=_severity(row.AnalysisResult.risk_score),
            top_reason=(
                row.AnalysisResult.top_features[0].get("name")
                if row.AnalysisResult.top_features
                else None
            ),
            received_at=row.Email.received_at,
        )
        for row in recent_q_rows
    ]

    has_pending_quarantine = quarantined_count > 0

    data = AnalysisStatsResponse(
        total_analysed=total_analysed,
        safe_count=safe_count,
        suspicious_count=suspicious_count,
        quarantined_count=quarantined_count,
        feedback_count=feedback_count,
        current_threshold=threshold,
        detection_driver_breakdown=detection_breakdown,
        severity_distribution=severity_dist,
        recent_quarantined=recent_quarantined,
        has_pending_quarantine=has_pending_quarantine,
    )

    await redis.setex(cache_key, _STATS_CACHE_TTL, data.model_dump_json())
    return data


# ---------------------------------------------------------------------------
# GET /dashboard/insights
# ---------------------------------------------------------------------------


@router.get(
    "/dashboard/insights",
    response_model=list[InsightItem],
    summary="AI insights panel (cached 60 s)",
)
async def get_dashboard_insights(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> list[InsightItem]:
    """Return insight cards for the dashboard insights panel.

    Delegates to insights_service.compute_insights() which handles caching
    (Redis TTL 60 s) and all three insight types:
      1. alert — quarantine spike (this week > 2× prev week)
      2. info  — current detection thresholds (always present)
      3. alert — analysis failures detected (any email.status == 'failed')
    """
    from app.services.insights_service import compute_insights  # noqa: PLC0415

    return await compute_insights(current_user.org_id, db, redis)
