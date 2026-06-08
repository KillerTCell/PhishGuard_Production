"""add training_samples table

Revision ID: f1a2b3c4d5e6
Revises: e5f6a7b8c9d0
Create Date: 2026-06-08
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "f1a2b3c4d5e6"
down_revision = "e5f6a7b8c9d0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "training_samples",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("org_id", UUID(as_uuid=True), sa.ForeignKey("organisations.id"), nullable=False),
        sa.Column("body_text", sa.Text, nullable=False),
        sa.Column("label", sa.String(16), nullable=False),
        sa.Column("source", sa.String(32), nullable=False, server_default="manual_paste"),
        sa.Column("used_in_training", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("label IN ('phishing', 'safe')", name="training_sample_label_check"),
        sa.CheckConstraint(
            "source IN ('manual_paste', 'eml_upload', 'quarantine_export')",
            name="training_sample_source_check",
        ),
    )
    op.create_index("ix_training_sample_org_label", "training_samples", ["org_id", "label"])


def downgrade() -> None:
    op.drop_index("ix_training_sample_org_label", table_name="training_samples")
    op.drop_table("training_samples")
