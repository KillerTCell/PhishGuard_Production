"""Section 4.2 -- FR-02, UC-02, UC-03: Email list and detail endpoints.

POST   /emails/upload   -- .eml file upload (≤5 MB)
GET    /emails          -- paginated list with risk_band filter (A-07)
GET    /emails/{id}     -- full detail with NLP features
DELETE /emails/{id}     -- hard delete (admin only, Privacy Act erasure)
"""
from __future__ import annotations

import math
import os
import tempfile
import uuid
from typing import Literal, Optional

import structlog
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import CurrentUser, get_current_user, get_db, require_admin
from app.models.analysis_result import AnalysisResult
from app.models.email import Email
from app.models.email_feature import EmailFeature
from app.schemas.common import RiskBand, Severity
from app.schemas.emails import (
    AttachmentMetadata,
    EmailDetail,
    EmailFeatureDetail,
    EmailListItem,
    EmailListResponse,
    EmailUploadResponse,
    LinkDetail,
)
from app.services import audit_service
from app.services.email_parser import EmailParseError, parse_eml

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["emails"])

_MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity(risk_score: int | None) -> Severity | None:
    """Derive the severity band from a risk score (0-100).

    ``Severity`` is not stored as a DB column — it is computed at read time
    (see :class:`~app.schemas.common.Severity` docstring).

    Args:
        risk_score: Integer 0-100, or ``None`` when analysis is still pending.

    Returns:
        :attr:`~Severity.critical`, :attr:`~Severity.high`,
        :attr:`~Severity.medium`, or :attr:`~Severity.low`;
        ``None`` when *risk_score* is ``None``.
    """
    if risk_score is None:
        return None
    if risk_score >= 90:
        return Severity.critical
    if risk_score >= 80:
        return Severity.high
    if risk_score >= 30:
        return Severity.medium
    return Severity.low


def _dispatch_analysis_chain(email_id: uuid.UUID) -> None:
    """Fire the Celery analysis chain for *email_id* (best-effort).

    Chain (Section 5.1 Task 1–5):
        parse_and_sanitise → extract_features → classify_email →
        generate_explanation → apply_outcome

    Errors are caught and logged at WARNING level so a Celery/Redis
    outage never blocks the HTTP response.
    """
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
            "analysis_chain_dispatch_failed",
            email_id=str(email_id),
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# POST /emails/upload
# ---------------------------------------------------------------------------


@router.post(
    "/emails/upload",
    response_model=EmailUploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload a .eml file for analysis",
)
async def upload_email(
    file: UploadFile = File(...),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EmailUploadResponse:
    """Ingest a .eml file and queue it for the analysis pipeline.

    Validation (Section 4.2):
        - ``Content-Type`` must be ``message/rfc822`` **or** the filename
          must end with ``.eml`` (browsers often send ``application/octet-stream``
          for file uploads).
        - File size ≤ 5 MB.
        - File must be parseable by :func:`~app.services.email_parser.parse_eml`.

    On success: saves raw bytes to ``/tmp/{uuid}.eml``, INSERTs the
    ``Email`` row with ``received_at`` from the parsed ``Date:`` header,
    and fires the Celery analysis chain.  Returns 202 immediately.

    UC-02 step 1.
    """
    # ── Content-type / filename validation ───────────────────────────────────
    filename_ok = file.filename and file.filename.lower().endswith(".eml")
    content_type_ok = file.content_type == "message/rfc822"
    if not (filename_ok or content_type_ok):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only .eml files are accepted (message/rfc822 or .eml extension)",
        )

    raw = await file.read()

    # ── Size validation ───────────────────────────────────────────────────────
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="File too large — maximum 5 MB",
        )

    # ── Parse and validate ────────────────────────────────────────────────────
    try:
        parsed = parse_eml(raw)
    except EmailParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid .eml file",
        ) from exc

    # ── Save raw bytes ────────────────────────────────────────────────────────
    # Use tempfile.gettempdir() instead of a hardcoded /tmp path (CWE-377).
    # Open with 'xb' (exclusive-create + binary) so the call fails atomically
    # if the UUID-named file already exists — prevents TOCTOU/symlink races.
    email_id = uuid.uuid4()
    tmp_path = os.path.join(tempfile.gettempdir(), f"{email_id}.eml")
    with open(tmp_path, "xb") as f_out:
        f_out.write(raw)

    # ── INSERT Email row ──────────────────────────────────────────────────────
    # received_at comes from the parsed Date: header; parse_eml always returns
    # a timezone-aware datetime (falls back to utcnow on malformed headers).
    email_record = Email(
        id=email_id,
        org_id=current_user.org_id,
        ingestion_source="upload",
        status="pending",
        received_at=parsed["received_at"],
    )
    db.add(email_record)
    await db.flush()

    # ── Fire analysis chain ───────────────────────────────────────────────────
    _dispatch_analysis_chain(email_id)

    logger.info("email_upload_queued", email_id=str(email_id), org_id=str(current_user.org_id))
    return EmailUploadResponse(email_id=email_id, status="pending")


# ---------------------------------------------------------------------------
# GET /emails
# ---------------------------------------------------------------------------


@router.get(
    "/emails",
    response_model=EmailListResponse,
    summary="Paginated email list with filters",
)
async def list_emails(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    risk_band: Optional[RiskBand] = Query(default=None),
    search: Optional[str] = Query(default=None, max_length=200),
    sort_by: Literal["received_at", "risk_score"] = Query(default="received_at"),
    sort_dir: Literal["asc", "desc"] = Query(default="desc"),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EmailListResponse:
    """Return paginated emails for this organisation.

    A-07 fix: risk_band maps to score ranges:
        critical  90-100
        high      80-89
        medium    30-79
        low       0-29
    """
    # Build query with LEFT JOIN to analysis_results for risk_score + classification
    base = (
        select(
            Email,
            AnalysisResult.risk_score,
            AnalysisResult.classification,
        )
        .outerjoin(AnalysisResult, AnalysisResult.email_id == Email.id)
        .where(Email.org_id == current_user.org_id)
    )

    if status_filter:
        base = base.where(Email.status == status_filter)

    # risk_band filter (A-07)
    if risk_band == RiskBand.critical:
        base = base.where(AnalysisResult.risk_score >= 90)
    elif risk_band == RiskBand.high:
        base = base.where(
            AnalysisResult.risk_score >= 80, AnalysisResult.risk_score < 90
        )
    elif risk_band == RiskBand.medium:
        base = base.where(
            AnalysisResult.risk_score >= 30, AnalysisResult.risk_score < 80
        )
    elif risk_band == RiskBand.low:
        base = base.where(AnalysisResult.risk_score < 30)

    if search:
        like = f"%{search}%"
        base = base.where(
            Email.sender.ilike(like) | Email.subject.ilike(like)
        )

    # Count
    total: int = (
        await db.execute(select(func.count()).select_from(base.subquery()))
    ).scalar_one()

    # Sort
    sort_col = (
        Email.received_at
        if sort_by == "received_at"
        else AnalysisResult.risk_score
    )
    if sort_dir == "desc":
        base = base.order_by(sort_col.desc().nullslast())
    else:
        base = base.order_by(sort_col.asc().nullsfirst())

    rows = (
        await db.execute(base.offset((page - 1) * page_size).limit(page_size))
    ).all()

    items = [
        EmailListItem(
            id=row.Email.id,
            sender=row.Email.sender,
            subject=row.Email.subject,
            risk_score=row.risk_score,
            severity=_severity(row.risk_score),
            status=row.Email.status,
            classification=row.classification,
            top_reason=None,  # derived from top_features in a service layer
            received_at=row.Email.received_at,
        )
        for row in rows
    ]

    pages = max(1, math.ceil(total / page_size))
    return EmailListResponse(items=items, total=total, page=page, pages=pages)


# ---------------------------------------------------------------------------
# GET /emails/{id}
# ---------------------------------------------------------------------------


@router.get(
    "/emails/{email_id}",
    response_model=EmailDetail,
    summary="Full email detail with analysis results",
)
async def get_email(
    email_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EmailDetail:
    """Return full email detail including NLP features and analysis results.

    JOIN across emails + analysis_results + email_features.
    org_id check enforced (multi-tenant isolation).
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

    # Fetch email features (top 3 by score_contribution desc)
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

    # Deserialise JSONB fields
    links = [
        LinkDetail(**lnk) if isinstance(lnk, dict) else lnk
        for lnk in (email.links or [])
    ]
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
        severity=_severity(analysis.risk_score if analysis else None),
        explanation=analysis.explanation if analysis else None,
        top_features=top_features,
        model_version=analysis.model_version if analysis else None,
        quarantined=email.status == "quarantined",
        added_to_training=email.added_to_training,
    )


# ---------------------------------------------------------------------------
# DELETE /emails/{id}  (Admin only — hard delete)
# ---------------------------------------------------------------------------


@router.delete(
    "/emails/{email_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Hard delete email and all child records (admin only)",
)
async def delete_email(
    email_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Permanently delete an email and all child rows (CASCADE).

    Used for Privacy Act erasure requests.  Writes audit_log.
    """
    result = await db.execute(
        select(Email).where(Email.id == email_id, Email.org_id == current_user.org_id)
    )
    email = result.scalar_one_or_none()
    if email is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    await db.delete(email)

    await audit_service.write_audit_log(
        db,
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="email_deleted",
        target_type="email",
        target_id=email_id,
        ip_address=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id"),
    )
