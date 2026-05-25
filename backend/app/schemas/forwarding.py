"""Pydantic v2 request/response schemas for routers/forwarding.py.

Covers Section 4.6 (FR-02, UC-02, UI Figure 12):
    GET   /forwarding              — forwarding address + IMAP connector status
    GET   /forwarding/emails       — paginated IMAP-ingested email list
    POST  /forwarding/test         — fire test email task (non-blocking)
    PATCH /forwarding/config       — save IMAP credentials (admin only)
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.schemas.common import ConnectorStatus, EmailStatus


# ---------------------------------------------------------------------------
# GET /forwarding
# ---------------------------------------------------------------------------


class SetupInstruction(BaseModel):
    """One step in the IMAP setup guide shown on the Forwarding Inbox page."""

    step: int
    text: str


class ForwardingStatusResponse(BaseModel):
    """Forwarding address + connector status (read-only, UI Figure 12)."""

    model_config = ConfigDict(from_attributes=True)

    forwarding_address: str
    connector_status: ConnectorStatus
    imap_user: Optional[str] = None
    setup_instructions: list[SetupInstruction]


# ---------------------------------------------------------------------------
# GET /forwarding/emails  — paginated IMAP-ingested emails
# ---------------------------------------------------------------------------


class ForwardingEmailItem(BaseModel):
    """Row in the 'Recent forwarded emails' table."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    sender: Optional[str] = None
    subject: Optional[str] = None
    risk_score: Optional[int] = None
    status: EmailStatus
    ingested_at: datetime


class ForwardingEmailListResponse(BaseModel):
    """Paginated list of IMAP-ingested emails."""

    items: list[ForwardingEmailItem]
    total: int
    page: int
    pages: int


# ---------------------------------------------------------------------------
# POST /forwarding/test
# ---------------------------------------------------------------------------


class ForwardingTestResponse(BaseModel):
    """202 returned immediately after forwarding_test Celery task is fired.

    P-04 fix: no blocking — SSE forwarding_test_complete fires when imap_poll
    naturally picks up the test email (≤60 s).
    """

    test_job_id: uuid.UUID
    message: str = "Test email sent. Check Recent forwarded emails."


# ---------------------------------------------------------------------------
# PATCH /forwarding/config  (Admin only)
# ---------------------------------------------------------------------------


class ForwardingConfigRequest(BaseModel):
    """IMAP credentials submitted by the admin on the Forwarding Inbox setup page."""

    imap_host: str = Field(min_length=1, max_length=253)
    imap_port: int = Field(default=993, ge=1, le=65535)
    imap_user: EmailStr
    imap_password: str = Field(min_length=1, max_length=256)


class ForwardingConfigResponse(BaseModel):
    """200 returned after saving IMAP config + running connection test."""

    connector_status: ConnectorStatus
