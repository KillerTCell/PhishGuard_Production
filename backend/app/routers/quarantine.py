"""Section 4.4 -- FR-05, UC-03, UC-05: Quarantine review endpoints.

GET  /quarantine                        -- paginated queue (A-06: total_count)
GET  /quarantine/{id}                   -- full detail
GET  /quarantine/{id}/digest-preview    -- HTML digest preview
POST /quarantine/{id}/confirm           -- mark confirmed_phishing
POST /quarantine/{id}/release           -- release to delivered
POST /quarantine/{id}/investigate       -- flag for investigation
POST /quarantine/{id}/send-digest       -- fire digest email (admin only)
"""
from __future__ import annotations

import json
import math
import uuid
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import CurrentUser, get_current_user, get_db, get_redis, require_admin
from app.models.analysis_result import AnalysisResult
from app.models.audit_log import AuditLog
from app.models.digest_log import DigestLog
from app.models.email import Email
from app.models.email_feature import EmailFeature
from app.models.feedback import Feedback
from app.schemas.emails import EmailDetail, EmailFeatureDetail, LinkDetail, AttachmentMetadata
from app.schemas.quarantine import (
    DigestPreviewResponse,
    QuarantineActionResponse,
    QuarantineListItem,
    QuarantineListResponse,
    SendDigestResponse,
)

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["quarantine"])


async def _write_audit(
    db: AsyncSession,
    action: str,
    current_user: CurrentUser,
    request: Request,
    target_id: Optional[uuid.UUID] = None,
    detail: Optional[dict] = None,
) -> None:
    """Append an audit log row for quarantine actions."""
    log = AuditLog(
        org_id=current_user.org_id,
        user_id=current_user.id,
        action=action,
        target_type="email",
        target_id=str(target_id) if target_id else None,
        ip_address=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id"),
        detail=detail or {},
    )
    db.add(log)


async def _publish_sse(redis: aioredis.Redis, org_id: uuid.UUID, event: dict) -> None:
    """Publish a scan_complete SSE event (best-effort)."""
    try:
        await redis.publish(
            f"org:{org_id}:events",
            json.dumps(event),
        )
    except Exception:
        logger.warning("sse_publish_failed", event=event.get("type"))


# ---------------------------------------------------------------------------
# GET /quarantine
# ---------------------------------------------------------------------------


@router.get(
    "/quarantine",
    response_model=QuarantineListResponse,
    summary="Paginated quarantine queue",
)
async def list_quarantine(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    search: Optional[str] = Query(default=None, max_length=200),
    sort_by: str = Query(default="received_at"),
    sort_dir: str = Query(default="desc"),
    feedback_state: Optional[str] = Query(default=None),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> QuarantineListResponse:
    """Return paginated emails in the quarantine queue.

    A-06 fix: returns ``total_count`` (not ``total``) for the '0 in queue' badge.
    """
    base = (
        select(Email, AnalysisResult)
        .outerjoin(AnalysisResult, AnalysisResult.email_id == Email.id)
        .where(Email.org_id == current_user.org_id, Email.status == "quarantined")
    )

    if search:
        like = f"%{search}%"
        base = base.where(Email.sender.ilike(like) | Email.subject.ilike(like))

    total_count: int = (
        await db.execute(select(func.count()).select_from(base.subquery()))
    ).scalar_one()

    sort_col = Email.received_at if sort_by == "received_at" else AnalysisResult.risk_score
    if sort_dir == "desc":
        base = base.order_by(sort_col.desc().nullslast())
    else:
        base = base.order_by(sort_col.asc().nullsfirst())

    rows = (
        await db.execute(base.offset((page - 1) * page_size).limit(page_size))
    ).all()

    items = [
        QuarantineListItem(
            id=row.Email.id,
            sender=row.Email.sender,
            subject=row.Email.subject,
            risk_score=row.AnalysisResult.risk_score if row.AnalysisResult else None,
            severity=row.AnalysisResult.severity if row.AnalysisResult else None,
            top_reason=None,
            status=row.Email.status,
            feedback_state=None,
            received_at=row.Email.received_at,
        )
        for row in rows
    ]

    pages = max(1, math.ceil(total_count / page_size))
    return QuarantineListResponse(
        items=items, total_count=total_count, page=page, pages=pages
    )


# ---------------------------------------------------------------------------
# GET /quarantine/{id}
# ---------------------------------------------------------------------------


@router.get(
    "/quarantine/{email_id}",
    response_model=EmailDetail,
    summary="Full quarantined email detail",
)
async def get_quarantine_detail(
    email_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EmailDetail:
    """Return full email detail — same schema as GET /emails/{id} plus feedback history."""
    result = await db.execute(
        select(Email, AnalysisResult)
        .outerjoin(AnalysisResult, AnalysisResult.email_id == Email.id)
        .where(
            Email.id == email_id,
            Email.org_id == current_user.org_id,
            Email.status == "quarantined",
        )
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Quarantined email not found",
        )

    email, analysis = row

    features = (
        await db.execute(
            select(EmailFeature)
            .where(EmailFeature.email_id == email_id)
            .order_by(EmailFeature.score_contribution.desc())
            .limit(7)
        )
    ).scalars().all()

    top_features = [
        EmailFeatureDetail(
            name=f.feature_name,
            value=float(f.feature_value) if f.feature_value is not None else 0.0,
            score_contribution=f.score_contribution or 0.0,
        )
        for f in features
    ]

    links = [LinkDetail(**lnk) if isinstance(lnk, dict) else lnk for lnk in (email.links or [])]
    attachments = [
        AttachmentMetadata(**att) if isinstance(att, dict) else att
        for att in (email.attachment_metadata or [])
    ]

    return EmailDetail(
        id=email.id,
        sender=email.sender,
        reply_to=email.reply_to,
        recipient_address=email.recipient_address,
        subject=email.subject,
        received_at=email.received_at,
        ingestion_source=email.ingestion_source,
        status=email.status,
        body_text=email.body_text,
        html_sanitised=email.html_sanitised,
        links=links,
        attachment_metadata=attachments,
        spf=email.spf,
        dkim=email.dkim,
        dmarc=email.dmarc,
        risk_score=analysis.risk_score if analysis else None,
        classification=analysis.classification if analysis else None,
        severity=analysis.severity if analysis else None,
        explanation=analysis.explanation if analysis else None,
        top_features=top_features,
        model_version=analysis.model_version if analysis else None,
        quarantined=True,
        added_to_training=email.added_to_training,
    )


# ---------------------------------------------------------------------------
# GET /quarantine/{id}/digest-preview
# ---------------------------------------------------------------------------


@router.get(
    "/quarantine/{email_id}/digest-preview",
    response_model=DigestPreviewResponse,
    summary="Preview the digest email before sending",
)
async def get_digest_preview(
    email_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DigestPreviewResponse:
    """Build HTML digest preview without sending.

    can_send=False if recipient_address is NULL (disable Send button in UI).
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

    features = (
        await db.execute(
            select(EmailFeature)
            .where(EmailFeature.email_id == email_id)
            .order_by(EmailFeature.score_contribution.desc())
            .limit(3)
        )
    ).scalars().all()

    top_features = [
        EmailFeatureDetail(
            name=f.feature_name,
            value=float(f.feature_value) if f.feature_value is not None else 0.0,
            score_contribution=f.score_contribution or 0.0,
        )
        for f in features
    ]

    can_send = email.recipient_address is not None

    # Build simple HTML preview (resend_service will use a full template)
    risk_score = analysis.risk_score if analysis else 0
    explanation = analysis.explanation if analysis else "Analysis pending."
    html_preview = (
        f"<h2>Security Alert: Potential Phishing Email</h2>"
        f"<p><strong>Risk Score:</strong> {risk_score}/100</p>"
        f"<p><strong>Assessment:</strong> {explanation}</p>"
        f"<p>Please review and confirm or release this email.</p>"
    )

    return DigestPreviewResponse(
        html_preview=html_preview,
        recipient_address=email.recipient_address,
        risk_score=risk_score,
        classification=analysis.classification if analysis else None,
        explanation=explanation,
        top_features=top_features,
        can_send=can_send,
    )


# ---------------------------------------------------------------------------
# POST /quarantine/{id}/confirm
# ---------------------------------------------------------------------------


@router.post(
    "/quarantine/{email_id}/confirm",
    response_model=QuarantineActionResponse,
    summary="Confirm as phishing",
)
async def confirm_phishing(
    email_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> QuarantineActionResponse:
    """Mark a quarantined email as confirmed phishing.

    Updates email.status, inserts feedback, publishes SSE.  UC-03 step 5.
    """
    email = (
        await db.execute(
            select(Email).where(Email.id == email_id, Email.org_id == current_user.org_id)
        )
    ).scalar_one_or_none()
    if email is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    email.status = "confirmed_phishing"
    db.add(
        Feedback(
            email_id=email_id,
            user_id=current_user.id,
            label="phishing",
            source="dashboard",
            created_at=datetime.now(timezone.utc),
        )
    )
    await _write_audit(db, "email_confirmed_phishing", current_user, request, email_id)
    await _publish_sse(
        redis, current_user.org_id,
        {"type": "scan_complete", "data": {"email_id": str(email_id), "status": "confirmed_phishing"}},
    )
    return QuarantineActionResponse(status="confirmed_phishing")


# ---------------------------------------------------------------------------
# POST /quarantine/{id}/release
# ---------------------------------------------------------------------------


@router.post(
    "/quarantine/{email_id}/release",
    response_model=QuarantineActionResponse,
    summary="Release quarantined email as safe",
)
async def release_email(
    email_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> QuarantineActionResponse:
    """Release a quarantined email back to delivered status.  UC-03 step 5."""
    email = (
        await db.execute(
            select(Email).where(Email.id == email_id, Email.org_id == current_user.org_id)
        )
    ).scalar_one_or_none()
    if email is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    email.status = "delivered"
    db.add(
        Feedback(
            email_id=email_id,
            user_id=current_user.id,
            label="safe",
            source="dashboard",
            created_at=datetime.now(timezone.utc),
        )
    )
    await _write_audit(db, "email_released", current_user, request, email_id)
    await _publish_sse(
        redis, current_user.org_id,
        {"type": "scan_complete", "data": {"email_id": str(email_id), "status": "delivered"}},
    )
    return QuarantineActionResponse(status="delivered")


# ---------------------------------------------------------------------------
# POST /quarantine/{id}/investigate
# ---------------------------------------------------------------------------


@router.post(
    "/quarantine/{email_id}/investigate",
    response_model=QuarantineActionResponse,
    summary="Flag email for further investigation",
)
async def flag_for_investigation(
    email_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> QuarantineActionResponse:
    """Insert a 'needs_investigation' feedback row.  Email status stays quarantined."""
    email = (
        await db.execute(
            select(Email).where(Email.id == email_id, Email.org_id == current_user.org_id)
        )
    ).scalar_one_or_none()
    if email is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    db.add(
        Feedback(
            email_id=email_id,
            user_id=current_user.id,
            label="needs_investigation",
            source="dashboard",
            created_at=datetime.now(timezone.utc),
        )
    )
    await _write_audit(db, "email_flagged_investigation", current_user, request, email_id)
    return QuarantineActionResponse(status="quarantined")


# ---------------------------------------------------------------------------
# POST /quarantine/{id}/send-digest  (Admin only)
# ---------------------------------------------------------------------------


@router.post(
    "/quarantine/{email_id}/send-digest",
    response_model=SendDigestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue digest email for recipient (admin only)",
)
async def send_digest(
    email_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> SendDigestResponse:
    """Validate can_send and fire send_digest Celery task.  UC-05 step 3."""
    email = (
        await db.execute(
            select(Email).where(Email.id == email_id, Email.org_id == current_user.org_id)
        )
    ).scalar_one_or_none()
    if email is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    if not email.recipient_address:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cannot send digest: recipient address is missing",
        )

    from app.core.security import sign_digest_token

    jti = str(uuid.uuid4())
    # Create digest log
    digest_log = DigestLog(
        email_id=email_id,
        signed_token_jti=jti,
        recipient_email=email.recipient_address,
    )
    db.add(digest_log)
    await db.flush()

    await _write_audit(
        db, "digest_sent", current_user, request, email_id,
        {"digest_log_id": str(digest_log.id)},
    )

    try:
        from app.tasks.digest_tasks import send_digest as send_digest_task

        send_digest_task.delay(str(email_id), str(digest_log.id))
    except Exception:
        logger.warning("digest_task_dispatch_failed", email_id=str(email_id))

    return SendDigestResponse(digest_log_id=digest_log.id)
