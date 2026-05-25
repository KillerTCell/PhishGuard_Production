"""Organisation ORM model — multi-tenant root (Section 3.1)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    SmallInteger,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Organisation(Base):
    """Multi-tenant root entity (Architecture ①).

    Every other table links to this via org_id FK.  The table-level
    CHECK constraint ``threshold_order`` (D-01 fix) guarantees that
    ``suspicious_threshold < phishing_threshold`` can never be violated
    by a direct database write — application-layer validation is a second
    line of defence only.

    Fields: 15 columns + 1 table-level CHECK (counted as 16 in the plan).
    """

    __tablename__ = "organisations"
    __table_args__ = (
        # D-01 FIX — enforced at DB level, cannot be bypassed by raw SQL
        CheckConstraint(
            "suspicious_threshold < phishing_threshold",
            name="threshold_order",
        ),
        CheckConstraint(
            "suspicious_threshold BETWEEN 0 AND 100",
            name="org_suspicious_range",
        ),
        CheckConstraint(
            "phishing_threshold BETWEEN 0 AND 100",
            name="org_phishing_range",
        ),
        CheckConstraint(
            "connector_status IN ('unconfigured','active','error')",
            name="org_connector_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)

    # ── Sensitivity thresholds (FR-05, UC-04) ───────────────────────────
    suspicious_threshold: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default="30"
    )
    phishing_threshold: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default="80"
    )

    # ── Auto-action settings (FR-05, UI Figure 14) ──────────────────────
    auto_quarantine_high_risk: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    prepend_subject_warning: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )

    # ── Forwarding inbox slug ────────────────────────────────────────────
    forwarding_address_slug: Mapped[str | None] = mapped_column(
        String(100), unique=True, nullable=True
    )

    # ── IMAP connector (Admin PATCH /forwarding/config) ──────────────────
    imap_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    imap_port: Mapped[int | None] = mapped_column(
        SmallInteger, nullable=True, server_default="993"
    )
    imap_user: Mapped[str | None] = mapped_column(String(254), nullable=True)
    # Decrypted in-memory only inside imap_worker — never logged or returned
    imap_password_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    connector_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="unconfigured"
    )

    # D-02 FIX — Celery Beat auto_delete_expired_emails uses this per org
    data_retention_days: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default="90"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # onupdate keeps the column current for ORM-issued UPDATEs;
    # the Alembic migration also creates a DB trigger for raw-SQL updates.
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
