"""EmailFeature ORM model (Section 3.4, FR-03)."""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class EmailFeature(Base):
    """NLP and heuristic feature extracted from a single email (FR-03).

    Each email produces exactly 7 rows — one per extractor defined in
    ``services/nlp_pipeline.py``.  BIGSERIAL PK is used instead of UUID
    to avoid overhead at scale (~7 rows × volume of emails).

    Feature names (arch step 3 '5 risk indicators' + 2 additional):
        urgency_language      — spaCy Matcher urgency patterns
        credential_request    — spaCy Matcher credential patterns
        link_mismatch         — tldextract displayed vs actual domain
        impersonation_language — spaCy Matcher impersonation patterns
        auth_failure          — SPF/DKIM/DMARC fail result
        grammar_quality       — textblob correction ratio (T-07 fix)
        known_bad_url         — PhishTank async lookup, Redis-cached 24 h

    ``score_contribution`` is normalised 0.0–1.0.  The top 3 rows by this
    field are stored in ``analysis_results.top_features`` for the UI
    evidence list (UI Figure 10–11).
    """

    __tablename__ = "email_features"
    __table_args__ = (
        CheckConstraint(
            "score_contribution BETWEEN 0.0 AND 1.0",
            name="email_feature_score_range",
        ),
        CheckConstraint(
            "feature_name IN ("
            "'urgency_language','credential_request','link_mismatch',"
            "'impersonation_language','auth_failure','grammar_quality',"
            "'known_bad_url')",
            name="email_feature_name_check",
        ),
        # Classifier lookup and email detail view JOIN
        Index("ix_email_feature_email_id", "email_id"),
    )

    # BIGSERIAL: high-volume table (~7 rows per email); avoids UUID overhead
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=False,
    )
    feature_name: Mapped[str] = mapped_column(String(100), nullable=False)
    # Scalar or evidence object e.g. {displayed:'Click here', actual:'evil.com', count:2}
    feature_value: Mapped[Any] = mapped_column(JSONB, nullable=False)
    score_contribution: Mapped[float] = mapped_column(
        Float, nullable=False, server_default=text("0.0")
    )
