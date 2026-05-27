"""AuditLog ORM model (Section 3.8, FR-01, FR-05, UC-04)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Valid action values — documented here for application-layer validation;
# not enforced by DB CHECK to allow forward-compatible values in future.
AUDIT_ACTIONS = frozenset(
    {
        "login_success",
        "login_failed",
        "login_blocked_inactive",  # S-06 fix
        "logout",
        "threshold_changed",
        "user_invited",
        "user_role_changed",
        "user_deactivated",
        "email_deleted",
        "email_released",
        "email_confirmed_phishing",
        "imap_config_updated",
        "export_generated",
        "export_failed",
        "task_failed",
        "auto_data_retention_delete",
    }
)

AUDIT_TARGET_TYPES = frozenset(
    {"email", "user", "settings", "imap_config", "export_job", "system"}
)


class AuditLog(Base):  # type: ignore[misc]  # SQLAlchemy declarative_base() returns Any
    """Append-only event log for compliance and admin review (FR-01, FR-05).

    IMPORTANT: This table must never be UPDATEd or DELETEd from.
    Service layer should only ever INSERT.  BIGSERIAL PK is intentional —
    the monotonically increasing integer makes chronological ordering
    trivial without a timestamp sort.

    D-08 fix: ``request_id`` (VARCHAR 36 — UUID length) correlates all
    writes made within a single HTTP request, making it possible to trace
    multi-table mutations from one API call in the structured log output.

    ``ip_address`` is PostgreSQL INET — stores IPv4 and IPv6 natively;
    set from the X-Forwarded-For header inserted by nginx.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        # GET /audit-log pagination — primary access pattern
        Index("ix_audit_log_org_created", "org_id", "created_at"),
        # GET /users/{id} recent actions
        Index("ix_audit_log_user_id", "user_id"),
    )

    # BIGSERIAL — append-only; monotonic ordering matches chronology
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organisations.id"),
        nullable=False,
    )
    # NULL for system/Celery-initiated actions (auto-delete, task_failed, etc.)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    # email | user | settings | imap_config | export_job | system
    target_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # UUID of affected record (email_id, user_id, export_job_id, etc.)
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    # Before/after data e.g. {before:{suspicious:30}, after:{suspicious:25}}
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # D-08 FIX — UUID of the HTTP request from structlog middleware
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # From X-Forwarded-For set by nginx — supports IPv4 and IPv6
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
