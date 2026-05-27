"""Feedback ORM model (Section 3.6, FR-07, Architecture ⑤)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Feedback(Base):  # type: ignore[misc]  # SQLAlchemy declarative_base() returns Any
    """Analyst or recipient label on a processed email (arch ⑤ feedback loop).

    D-06 fix: there is deliberately **NO UNIQUE constraint** on ``email_id``.
    UC-05 edge flow: 'keep the most recent valid label and retain prior labels
    for audit'.  The export service selects the most-recent label per
    ``email_id`` for the training dataset; older labels are retained for
    the full audit trail.

    ``user_id`` is nullable — it is NULL when the label is submitted via a
    signed digest email link (the recipient is not a dashboard user and has
    no account).

    Sources:
        dashboard    — analyst clicks 'Confirm Phishing' / 'Mark Safe' /
                       'Needs Investigation' in the quarantine queue
        digest_link  — recipient clicks action link in the digest email
        manual_paste — analyst ticks checkbox on the paste analysis screen
    """

    __tablename__ = "feedback"
    __table_args__ = (
        CheckConstraint(
            "label IN ('phishing','safe','needs_investigation')",
            name="feedback_label_check",
        ),
        CheckConstraint(
            "source IN ('dashboard','digest_link','manual_paste')",
            name="feedback_source_check",
        ),
        # JOIN on email detail view
        Index("ix_feedback_email_id", "email_id"),
        # Export date-range filtering
        Index("ix_feedback_created_at", "created_at"),
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
    # NULL when submitted via signed digest link — recipient has no account
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    label: Mapped[str] = mapped_column(String(25), nullable=False)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
