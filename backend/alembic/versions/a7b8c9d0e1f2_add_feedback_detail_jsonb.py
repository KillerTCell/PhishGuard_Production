"""Add feedback.detail JSONB column for contributor review comments.

The contributor opinion flow (Change 4) stores
{"comment": "<reasoning>", "source": "contributor_review"} per feedback row.

Revision ID: a7b8c9d0e1f2
Revises: f1a2b3c4d5e6
"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "a7b8c9d0e1f2"
down_revision: Union[str, None] = "f1a2b3c4d5e6"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    op.add_column("feedback", sa.Column("detail", JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("feedback", "detail")
