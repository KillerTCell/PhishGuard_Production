"""DigestLog ORM model (Section 3.7, FR-06, UC-05)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    SmallInteger,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class DigestLog(Base):  # type: ignore[misc]  # SQLAlchemy declarative_base() returns Any
    """Record of a quarantine digest email sent to an end-recipient (FR-06).

    D-07 fix: ``retry_count`` tracks Resend SDK retry attempts.  The
    Celery task retries up to 3 times before setting ``status='failed'``.

    The ``signed_token_jti`` is checked in ``GET /digest/action`` before
    any action is applied — a second request with the same JTI returns
    410 Gone (replay prevention, UC-05 edge flow).

    Token lifetime: 72 hours from ``sent_at`` (``token_expires_at``).
    Expired link returns 410 Gone (UC-05 edge flow).
    """

    __tablename__ = "digest_log"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','sent','failed')",
            name="digest_log_status_check",
        ),
        CheckConstraint(
            "action_taken IN ('confirmed_phishing','marked_safe')",
            name="digest_log_action_taken_check",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Digest destination — copied from emails.recipient_address at send time
    recipient_address: Mapped[str] = mapped_column(String(320), nullable=False)
    # NULL until the Resend SDK call succeeds
    sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(10), nullable=False, server_default="pending"
    )
    # D-07 FIX — incremented on each failed Resend attempt; max 3 retries
    retry_count: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text("0")
    )
    # 64-char HMAC hex; UNIQUE enforces single-use replay prevention
    signed_token_jti: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )
    # 72-hour window from sent_at (UC-05: 'Expired link: reject action')
    token_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # NULL until recipient clicks an action link
    action_taken: Mapped[str | None] = mapped_column(String(25), nullable=True)
    action_taken_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
