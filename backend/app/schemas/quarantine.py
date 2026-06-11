"""Pydantic v2 request/response schemas for routers/quarantine.py.

Covers Section 4.4 (FR-05, UC-03, UC-05):
    GET  /quarantine                        — paginated list (A-06: total_count)
    GET  /quarantine/{id}                   — full detail (reuses EmailDetail)
    GET  /quarantine/{id}/digest-preview    — Recipient Digest preview
    POST /quarantine/{id}/confirm           — mark confirmed_phishing
    POST /quarantine/{id}/release           — release to delivered
    POST /quarantine/{id}/investigate       — mark needs investigation
    POST /quarantine/{id}/send-digest       — fire digest email (admin)
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import Classification, EmailStatus, FeedbackState, Severity
from app.schemas.emails import EmailFeatureDetail


# ---------------------------------------------------------------------------
# GET /quarantine  — list
# ---------------------------------------------------------------------------


class QuarantineListItem(BaseModel):
    """Compact row returned in the quarantine queue (UI Figure 6)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    sender: Optional[str] = None
    subject: Optional[str] = None
    risk_score: Optional[int] = None
    severity: Optional[Severity] = None
    top_reason: Optional[str] = None
    status: EmailStatus
    feedback_state: Optional[FeedbackState] = None
    received_at: datetime


class QuarantineListResponse(BaseModel):
    """Paginated quarantine list.

    A-06 fix: total_count (not total) drives the '0 in queue' badge (UC-03 step 1).
    """

    items: list[QuarantineListItem]
    total_count: int
    page: int
    pages: int


# ---------------------------------------------------------------------------
# GET /quarantine/{id}/digest-preview
# ---------------------------------------------------------------------------


class DigestPreviewResponse(BaseModel):
    """HTML preview of the digest email before it is sent to the recipient.

    can_send=False when recipient_address is NULL (UI should disable Send button).
    UI Figure 7 'Daily Security Summary' preview card.
    """

    html_preview: str
    recipient_address: Optional[str] = None
    risk_score: Optional[int] = None
    classification: Optional[Classification] = None
    explanation: Optional[str] = None
    top_features: list[EmailFeatureDetail] = []
    can_send: bool


# ---------------------------------------------------------------------------
# POST /quarantine/{id}/confirm|release|investigate
# ---------------------------------------------------------------------------


class QuarantineActionBody(BaseModel):
    """Optional request body for quarantine actions.

    The contributor opinion flow submits a free-text comment which is stored
    in feedback.detail JSONB as {"comment": ..., "source": "contributor_review"}.
    """

    comment: Optional[str] = Field(None, max_length=1000)


class QuarantineActionResponse(BaseModel):
    """200 returned after any quarantine action (confirm / release / investigate)."""

    status: EmailStatus


# ---------------------------------------------------------------------------
# POST /quarantine/{id}/send-digest  (Admin only)
# ---------------------------------------------------------------------------


class SendDigestResponse(BaseModel):
    """202 returned immediately when digest send is queued."""

    digest_log_id: uuid.UUID
