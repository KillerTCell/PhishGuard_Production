"""Section 4.6 -- FR-02, UC-02: Forwarding Inbox endpoints.

GET   /forwarding               -- forwarding address + connector status
GET   /forwarding/emails        -- paginated IMAP-ingested email list
POST  /forwarding/test          -- fire test email (non-blocking)
PATCH /forwarding/config        -- save IMAP credentials (admin only)
"""
from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.core.security import fernet_encrypt
from app.dependencies import CurrentUser, get_current_user, get_db, require_admin
from app.models.audit_log import AuditLog
from app.models.email import Email
from app.models.organisation import Organisation
from app.schemas.forwarding import (
    ForwardingConfigRequest,
    ForwardingConfigResponse,
    ForwardingEmailItem,
    ForwardingEmailListResponse,
    ForwardingStatusResponse,
    ForwardingTestResponse,
    SetupInstruction,
)

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["forwarding"])

_SETUP_INSTRUCTIONS = [
    SetupInstruction(step=1, text="In your email client, create a forwarding rule."),
    SetupInstruction(step=2, text="Forward suspicious emails to your PhishGuard address below."),
    SetupInstruction(step=3, text="Configure IMAP to allow PhishGuard to poll the mailbox."),
    SetupInstruction(step=4, text="Click 'Send Test Message' to verify the connection."),
]


# ---------------------------------------------------------------------------
# GET /forwarding
# ---------------------------------------------------------------------------


@router.get(
    "/forwarding",
    response_model=ForwardingStatusResponse,
    summary="Forwarding address and IMAP connector status",
)
async def get_forwarding_status(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ForwardingStatusResponse:
    """Return the org's forwarding address and current IMAP connector status."""
    org = (
        await db.execute(
            select(Organisation).where(Organisation.id == current_user.org_id)
        )
    ).scalar_one()

    forwarding_address = (
        f"scan+{org.forwarding_address_slug}@{app_settings.FORWARDING_DOMAIN}"
    )
    return ForwardingStatusResponse(
        forwarding_address=forwarding_address,
        connector_status=org.connector_status,
        imap_user=org.imap_user,
        setup_instructions=_SETUP_INSTRUCTIONS,
    )


# ---------------------------------------------------------------------------
# GET /forwarding/emails
# ---------------------------------------------------------------------------


@router.get(
    "/forwarding/emails",
    response_model=ForwardingEmailListResponse,
    summary="Paginated IMAP-ingested email list",
)
async def list_forwarding_emails(
    page: int = 1,
    page_size: int = 20,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ForwardingEmailListResponse:
    """Return emails received via IMAP (ingestion_source='imap')."""
    base = select(Email).where(
        Email.org_id == current_user.org_id,
        Email.ingestion_source == "imap",
    )

    total: int = (
        await db.execute(select(func.count()).select_from(base.subquery()))
    ).scalar_one()

    rows = (
        await db.execute(
            base.order_by(Email.ingested_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars().all()

    items = [
        ForwardingEmailItem(
            id=r.id,
            sender=r.sender,
            subject=r.subject,
            risk_score=None,  # joined from analysis_results in a later optimisation
            status=r.status,
            ingested_at=r.ingested_at,
        )
        for r in rows
    ]
    pages = max(1, math.ceil(total / page_size))
    return ForwardingEmailListResponse(items=items, total=total, page=page, pages=pages)


# ---------------------------------------------------------------------------
# POST /forwarding/test
# ---------------------------------------------------------------------------


@router.post(
    "/forwarding/test",
    response_model=ForwardingTestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Send a test forwarded email (non-blocking)",
)
async def test_forwarding(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ForwardingTestResponse:
    """Fire a forwarding_test Celery task and return immediately.

    P-04 fix: no blocking wait for IMAP response.
    SSE event 'forwarding_test_complete' fires when imap_poll picks up
    the test email naturally (within <= 60 s).
    """
    test_job_id = uuid.uuid4()

    try:
        from app.tasks.imap_tasks import forwarding_test

        forwarding_test.delay(str(current_user.org_id), str(current_user.id))
    except Exception:
        logger.warning("forwarding_test_dispatch_failed", org_id=str(current_user.org_id))

    return ForwardingTestResponse(
        test_job_id=test_job_id,
        message="Test email sent. Check Recent forwarded emails.",
    )


# ---------------------------------------------------------------------------
# PATCH /forwarding/config  (Admin only)
# ---------------------------------------------------------------------------


@router.patch(
    "/forwarding/config",
    response_model=ForwardingConfigResponse,
    summary="Save IMAP credentials and test connection (admin only)",
)
async def update_forwarding_config(
    body: ForwardingConfigRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ForwardingConfigResponse:
    """Save IMAP configuration with Fernet-encrypted password.

    After saving, immediately tests the IMAP connection and sets
    connector_status accordingly.  Writes audit_log.
    """
    org = (
        await db.execute(
            select(Organisation).where(Organisation.id == current_user.org_id)
        )
    ).scalar_one()

    org.imap_host = body.imap_host
    org.imap_port = body.imap_port
    org.imap_user = str(body.imap_user)
    org.imap_password_enc = fernet_encrypt(body.imap_password)

    # Test connection
    connector_status = "active"
    try:
        import asyncio
        import imaplib

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            _test_imap_connection,
            body.imap_host,
            body.imap_port,
            str(body.imap_user),
            body.imap_password,
        )
    except Exception as exc:
        logger.warning("imap_test_failed", error=str(exc))
        connector_status = "error"

    org.connector_status = connector_status

    log = AuditLog(
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="imap_config_updated",
        ip_address=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id"),
        detail={"imap_user": str(body.imap_user), "connector_status": connector_status},
    )
    db.add(log)

    return ForwardingConfigResponse(connector_status=connector_status)


def _test_imap_connection(host: str, port: int, user: str, password: str) -> None:
    """Synchronous IMAP connection test run in thread executor."""
    import imaplib
    import ssl

    ctx = ssl.create_default_context()
    with imaplib.IMAP4_SSL(host, port, ssl_context=ctx) as imap:
        imap.login(user, password)
