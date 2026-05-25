"""Pydantic v2 request/response schemas for routers/settings.py.

Covers Section 4.8 (FR-05, UC-04, UC-06):
    GET  /settings                    — read org thresholds + flags
    PATCH /settings                   — update (admin, A-03 cross-validation)
    POST /settings/export             — queue export job (A-04 enum, A-05 scope)
    GET  /settings/export/{job_id}    — download or status poll (A-02 FileResponse)
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.common import ExportDateRange, ExportFormat, ExportStatus, LabelFilter


# ---------------------------------------------------------------------------
# GET /settings
# ---------------------------------------------------------------------------


class SettingsResponse(BaseModel):
    """Current detection thresholds and behaviour flags for the organisation."""

    model_config = ConfigDict(from_attributes=True)

    suspicious_threshold: int
    phishing_threshold: int
    auto_quarantine_high_risk: bool
    prepend_subject_warning: bool


# ---------------------------------------------------------------------------
# PATCH /settings  (Admin only)
# ---------------------------------------------------------------------------


class SettingsUpdateRequest(BaseModel):
    """Partial update of org settings.

    A-03 fix: 422 if suspicious_threshold >= phishing_threshold.
    All fields are optional — only send what changes.
    """

    suspicious_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    phishing_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    auto_quarantine_high_risk: Optional[bool] = None
    prepend_subject_warning: Optional[bool] = None

    @model_validator(mode="after")
    def validate_threshold_order(self) -> "SettingsUpdateRequest":
        """Enforce suspicious < phishing when both thresholds are supplied.

        UC-04 step 4 validation — mirrors the DB CHECK constraint (D-01).
        """
        s = self.suspicious_threshold
        p = self.phishing_threshold
        if s is not None and p is not None and s >= p:
            raise ValueError(
                "Suspicious threshold must be strictly less than phishing threshold."
            )
        return self


# ---------------------------------------------------------------------------
# POST /settings/export  (Admin only)
# ---------------------------------------------------------------------------


class ExportScope(BaseModel):
    """Estimated email counts for each label category (A-05 fix).

    Returned immediately in the 202 so the UI can show the 'Estimated scope' card.
    """

    emails: int
    phishing: int
    safe: int
    review: int


class ExportCreateRequest(BaseModel):
    """Parameters for a new export job.

    A-04 fix: date_range is an enum matching the UI dropdown options.
    """

    format: ExportFormat
    date_range: ExportDateRange
    label_filter: LabelFilter = LabelFilter.all


class ExportCreateResponse(BaseModel):
    """202 returned immediately after export job is queued."""

    job_id: uuid.UUID
    estimated_scope: ExportScope


# ---------------------------------------------------------------------------
# GET /settings/export/{job_id}  (Admin only)
# ---------------------------------------------------------------------------


class ExportJobStatusResponse(BaseModel):
    """Polling response when the job is not yet ready.

    A-02 fix: when ready the router returns FileResponse directly (not this schema).
    """

    model_config = ConfigDict(from_attributes=True)

    job_id: uuid.UUID
    status: ExportStatus
    estimated_scope: Optional[ExportScope] = None
    format: Optional[ExportFormat] = None
    created_at: Optional[datetime] = None
    error_message: Optional[str] = None
