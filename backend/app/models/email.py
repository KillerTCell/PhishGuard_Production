"""Email ORM model (Section 3.3, FR-02, UC-02)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Email(Base):  # type: ignore[misc]  # SQLAlchemy declarative_base() returns Any
    """Ingested email record — the central entity of the analysis pipeline.

    Ingestion sources:
        imap    — polled from org forwarding mailbox via imap_poll_all_orgs
        upload  — .eml file uploaded via POST /emails/upload
        paste   — raw email pasted via POST /analysis/paste

    Status state machine (arch ④):
        pending → delivered | flagged | quarantined | confirmed_phishing | failed

    D-04: ``recipient_address`` = primary To: address only.
    CC/BCC are out of MVP scope.

    Attachment binary content is never stored — only metadata (data
    minimisation, ethics section of the proposal).
    """

    __tablename__ = "emails"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','delivered','flagged','quarantined',"
            "'confirmed_phishing','failed')",
            name="email_status_check",
        ),
        CheckConstraint(
            "ingestion_source IN ('imap','upload','paste')",
            name="email_ingestion_source_check",
        ),
        CheckConstraint(
            "spf IN ('pass','fail','none','neutral','softfail')",
            name="email_spf_check",
        ),
        CheckConstraint(
            "dkim IN ('pass','fail','none')",
            name="email_dkim_check",
        ),
        CheckConstraint(
            "dmarc IN ('pass','fail','none')",
            name="email_dmarc_check",
        ),
        # Dashboard pagination (most-used query path)
        Index("ix_email_org_received", "org_id", "received_at"),
        # Quarantine queue filter
        Index("ix_email_status", "status"),
        # Forwarding inbox filter (GET /forwarding/emails)
        Index("ix_email_ingestion_source", "ingestion_source"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organisations.id"),
        nullable=False,
    )

    # ── Headers ─────────────────────────────────────────────────────────
    sender: Mapped[str | None] = mapped_column(String(320), nullable=True)
    reply_to: Mapped[str | None] = mapped_column(String(320), nullable=True)
    # Primary To: only — CC/BCC out of MVP scope (D-04)
    recipient_address: Mapped[str | None] = mapped_column(String(320), nullable=True)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Body ────────────────────────────────────────────────────────────
    # Plain-text preferred over HTML for analysis (text/plain MIME part)
    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    # bleach.clean() output — scripts/iframes stripped (NFR-2 XSS prevention)
    # This field is shown in UI; raw HTML is never exposed to the frontend
    html_sanitised: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Extracted link and attachment data ──────────────────────────────
    # [{displayed_text, actual_href, is_mismatch}]
    links: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    # [{filename, size, mime_type}] — no binary content (data minimisation)
    attachment_metadata: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )

    # ── Authentication headers (checkdmarc parsed) ───────────────────────
    spf: Mapped[str | None] = mapped_column(String(10), nullable=True)
    dkim: Mapped[str | None] = mapped_column(String(10), nullable=True)
    dmarc: Mapped[str | None] = mapped_column(String(10), nullable=True)

    # ── Timestamps ──────────────────────────────────────────────────────
    # Original Date: header value
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # System ingest time — used for data-retention calculation
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # ── Raw upload bytes (upload source only) ───────────────────────────
    # Stores the raw .eml bytes for uploaded files so the parse_and_sanitise
    # Celery task can access them without relying on a shared /tmp/ directory.
    # The worker container has a different /tmp/ from the API container, so
    # files written to /tmp/ by the API are not accessible to the worker.
    # Cleared after parse_and_sanitise completes to reclaim storage.
    raw_bytes: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # ── Lifecycle ───────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        String(25), nullable=False, server_default="pending"
    )
    ingestion_source: Mapped[str] = mapped_column(String(10), nullable=False)
    # Set True when analyst ticks 'Add to training dataset' (UI Figure 8)
    added_to_training: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
