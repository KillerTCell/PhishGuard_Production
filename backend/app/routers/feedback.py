"""Section 4.7 -- FR-07, Architecture feedback-loop: POST /feedback/{email_id}

Analyst submits a label for a processed email.  Multiple rows per email_id
are intentional (D-06 -- no UNIQUE constraint on feedback.email_id).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import CurrentUser, get_current_user, get_db
from app.models.email import Email
from app.models.feedback import Feedback
from app.schemas.feedback import FeedbackRequest

router = APIRouter(tags=["feedback"])


@router.post(
    "/feedback/{email_id}",
    status_code=status.HTTP_201_CREATED,
    summary="Submit feedback label for an email",
)
async def submit_feedback(
    email_id: uuid.UUID,
    body: FeedbackRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Record an analyst feedback label for an email.

    Validates that the email belongs to the analyst's organisation
    (multi-tenant isolation, Architecture section ②).

    D-06: multiple feedback rows per email_id are allowed -- this supports
    the full audit history of analyst decisions on a single email.
    """
    result = await db.execute(
        select(Email).where(Email.id == email_id, Email.org_id == current_user.org_id)
    )
    email = result.scalar_one_or_none()
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Email not found",
        )

    feedback = Feedback(
        email_id=email_id,
        user_id=current_user.id,
        label=body.label.value,
        source="dashboard",
        created_at=datetime.now(timezone.utc),
    )
    db.add(feedback)
    # Commit happens automatically in get_db() on exit
    return {}
