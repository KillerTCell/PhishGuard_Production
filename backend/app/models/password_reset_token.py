"""PasswordResetToken ORM model (Section 3.10, FR-01) — D-09 fix."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func, text
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class PasswordResetToken(Base):  # type: ignore[misc]  # SQLAlchemy declarative_base() returns Any
    """Single-use password reset token (D-09 fix — new table in v3).

    D-09: prior plan had no dedicated table for password reset tokens,
    leaving the flow untracked and enabling token reuse.  This table fixes
    that gap.

    Flow (UC-01 edge flow):
        1. User submits POST /auth/forgot-password.
        2. Service generates an HMAC-signed opaque token, bcrypt-hashes it,
           INSERTs a row here with 1-hour expiry.
        3. Resend sends the raw token in an email link.
        4. User clicks → POST /auth/reset-password: service verifies the
           raw token against ``token_hash``, checks ``expires_at`` and
           ``used_at`` (NULL = not yet consumed), applies new password,
           then sets ``used_at = now()``.

    Expiry: 1 hour from ``created_at``.
    POST /auth/forgot-password always returns 202 regardless of whether the
    email exists (UC-01: prevents user enumeration).
    """

    __tablename__ = "password_reset_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    # bcrypt hash of the HMAC-signed opaque raw token sent in the reset email
    # VARCHAR(72) = bcrypt max output length
    token_hash: Mapped[str] = mapped_column(String(72), nullable=False, unique=True)
    # 1-hour expiry (UC-01 edge flow)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # NULL until the reset is successfully consumed — set on POST /auth/reset-password
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # IP that called POST /auth/forgot-password — audit trail
    ip_requested_from: Mapped[str | None] = mapped_column(INET, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
