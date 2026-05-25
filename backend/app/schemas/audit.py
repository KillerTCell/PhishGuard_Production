"""Pydantic v2 request/response schemas for routers/audit.py.

Covers Section 4.12 (A-10 fix — GET /audit-log was referenced in Architecture ②
and UI Figure 18 but had no endpoint definition in v2).

    GET /audit-log   — paginated audit log (admin only)
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# GET /audit-log  — list item and paginated response
# ---------------------------------------------------------------------------


class AuditLogListItem(BaseModel):
    """Single audit log row.

    D-08 fix: request_id (VARCHAR 36) traces a single HTTP request across
    multiple audit rows.  ip_address is INET — serialised as str here.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[uuid.UUID] = None
    user_name: Optional[str] = None   # denormalised full_name for display
    action: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    detail: Optional[Any] = None      # JSONB — arbitrary dict
    ip_address: Optional[str] = None  # INET coerced to str
    created_at: datetime
    request_id: Optional[str] = None  # VARCHAR 36 (UUID string)


class AuditLogListResponse(BaseModel):
    """Paginated audit log list.

    All rows are filtered by org_id.  Supports filter by user_id and action.
    Drives UI Figure 18 'Recent admin actions' panel.
    """

    items: list[AuditLogListItem]
    total: int
    page: int
    pages: int
