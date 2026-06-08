"""TrainingSample ORM model — accumulates labelled email text for ML retraining."""
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
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class TrainingSample(Base):  # type: ignore[misc]
    """A labelled email body stored for ML model retraining.

    Samples accumulate permanently — they are never deleted by the retrain
    process.  Admins may remove individual mislabelled entries via
    DELETE /training/samples/{id}.

    The used_in_training flag is informational: it is set True after each
    retrain, but ALL rows (including those already flagged) are included in
    every subsequent retrain.
    """

    __tablename__ = "training_samples"
    __table_args__ = (
        CheckConstraint(
            "label IN ('phishing', 'safe')",
            name="training_sample_label_check",
        ),
        CheckConstraint(
            "source IN ('manual_paste', 'eml_upload', 'quarantine_export')",
            name="training_sample_source_check",
        ),
        Index("ix_training_sample_org_label", "org_id", "label"),
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
    body_text: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="manual_paste")
    used_in_training: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
