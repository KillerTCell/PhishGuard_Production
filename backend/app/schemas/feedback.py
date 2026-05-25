"""Pydantic v2 request/response schemas for routers/feedback.py and digest.py.

Covers Section 4.7 (FR-07, Architecture ⑤):
    POST /feedback/{email_id}   — analyst submits label
    GET  /digest/action         — public HMAC-signed action link (confirm|release)
"""
from __future__ import annotations

from pydantic import BaseModel

from app.schemas.common import FeedbackLabel


# ---------------------------------------------------------------------------
# POST /feedback/{email_id}
# ---------------------------------------------------------------------------


class FeedbackRequest(BaseModel):
    """Analyst feedback label for a processed email.

    D-06: feedback table has NO UNIQUE constraint on email_id — multiple
    feedback rows per email are intentional for audit history.
    """

    label: FeedbackLabel


# ---------------------------------------------------------------------------
# GET /digest/action  (Public — HMAC signed, Section 4.4 + 4.7)
# ---------------------------------------------------------------------------

# Query params: token (str) + action (enum confirm|release)
# Response: HTML page rendered server-side — no Pydantic response model.
# The action values map to:
#   confirm → digest_log.action_taken = 'confirmed_phishing'
#              feedback.label = 'phishing', source='digest_link'
#   release → digest_log.action_taken = 'marked_safe'
#              feedback.label = 'safe', source='digest_link'
#
# Error responses (also HTML):
#   400  tampered token (HMAC verify failed)
#   410  replay / expired  (JTI already consumed or >72h)
#
# CSP header always included (S-05 fix):
#   Content-Security-Policy: default-src 'self'

class DigestActionParam(BaseModel):
    """Validated query parameters for GET /digest/action.

    Used only for internal validation — the route still returns HTML,
    not this schema.
    """

    token: str
    action: str  # 'confirm' | 'release' — validated in the route handler
