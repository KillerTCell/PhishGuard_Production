"""InviteToken ORM model (Section 3.9, FR-01)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class InviteToken(Base):
    """Single-use org member invite token (FR-01, admin UC).

    The raw token is sent in the email link; only its bcrypt hash is stored
    (``token_hash``).  On acceptance the invite form calls
    ``POST /auth/register`` with the raw token; the service layer verifies
    it against the stored hash and sets ``used_at``.

    Expiry: 48 hours from ``created_at``.
    """

    __tablename__ = "invite_tokens"
    __table_args__ = (
        CheckConstraint(
            "role IN ('admin','analyst')",
            name="invite_token_role_check",
        ),
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
    invited_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
    )
    # Pre-filled in the accept-invite registration form
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    # bcrypt hash of the raw invite token sent in the email link
    # VARCHAR(72) = bcrypt max output length
    token_hash: Mapped[str] = mapped_column(String(72), nullable=False, unique=True)
    # 48-hour expiry from created_at
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # NULL until accepted
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
