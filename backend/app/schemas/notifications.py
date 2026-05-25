"""Pydantic v2 request/response schemas for routers/notifications.py.

Covers Section 4.11 (A-01 fix — PATCH /notifications/read was referenced in
Section 6 notification bell logic but had no endpoint definition in v2).

    PATCH /notifications/read   — mark all unread notifications as read
"""
from __future__ import annotations

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# PATCH /notifications/read
# ---------------------------------------------------------------------------


class NotificationsReadResponse(BaseModel):
    """200 returned after resetting the unread counter to zero.

    Redis SET notif:{user_id}:unread = 0.  No DB write.
    A-01 fix: endpoint previously referenced in frontend but undefined.
    """

    unread_count: int = 0
