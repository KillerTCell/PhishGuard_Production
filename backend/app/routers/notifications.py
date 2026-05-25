"""Section 4.11 -- A-01 fix: PATCH /notifications/read

Resets the unread notification counter for the current user.
No DB write -- Redis SET only.

A-01 fix: this endpoint was referenced in Section 6 (notification bell logic)
but had no definition in v2.
"""
from __future__ import annotations

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends

from app.dependencies import CurrentUser, get_current_user, get_redis
from app.schemas.notifications import NotificationsReadResponse

router = APIRouter(tags=["notifications"])


@router.patch(
    "/notifications/read",
    response_model=NotificationsReadResponse,
    summary="Mark all notifications as read",
)
async def mark_notifications_read(
    current_user: CurrentUser = Depends(get_current_user),
    redis: aioredis.Redis = Depends(get_redis),
) -> NotificationsReadResponse:
    """Reset the unread notification counter to zero.

    Redis SET ``notif:{user_id}:unread = 0``.  No DB write.
    Called when the user clicks the notification bell icon in the top bar.
    """
    await redis.set(f"notif:{current_user.id}:unread", 0)
    return NotificationsReadResponse(unread_count=0)
