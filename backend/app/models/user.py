"""User ORM model (Section 3.2, FR-01, UC-01)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class User(Base):
    """Authenticated user within an organisation.

    D-03: ``email`` IS the username — there is no separate ``username``
    column.  FR-01 documentation refers to 'username' which maps directly
    to this field.

    Roles:
        admin   — full sidebar + User Management (UC-01 main flow step 4)
        analyst — User Management tab hidden; read/quarantine access only
    """

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", name="uq_user_email"),
        CheckConstraint("role IN ('admin','analyst')", name="user_role_check"),
        Index("ix_user_org_id", "org_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organisations.id", ondelete="CASCADE"),
        nullable=False,
    )
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    # D-03: email serves as the login username — no separate username column
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    # bcrypt output; cost factor ≥12 per NFR-2; 72 chars = bcrypt max output
    password_hash: Mapped[str] = mapped_column(String(72), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    # Debounced 5-min update on each authenticated request (UI Figure 17)
    last_active_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
