"""add_raw_bytes_to_emails

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-05-31 00:00:00.000000

Add raw_bytes BYTEA column to emails table so uploaded .eml files can be
stored in the database instead of /tmp/.  This is necessary because the API
container and the Celery worker container do not share a filesystem — files
written to /tmp/ by the API are invisible to the worker.

The column is nullable and cleared (set to NULL) by parse_and_sanitise after
the bytes have been consumed, so it does not hold data long-term.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "emails",
        sa.Column("raw_bytes", sa.LargeBinary(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("emails", "raw_bytes")
