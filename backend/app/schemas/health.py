"""Pydantic v2 response schema for routers/health.py.

Covers Section 4.13 (N-03 fix -- GET /health):
    GET /health  -- Docker HEALTHCHECK + nginx probe + external monitoring

Response is 200 when all dependencies are up; 503 when any are down.
No auth required (high-frequency probes must not incur auth overhead).
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """System health payload.

    Async checks performed per request:
        db           -- SELECT 1 against the PostgreSQL connection pool
        redis        -- Redis PING
        model_loaded -- os.path.exists('ml/model.pkl')

    Returns 503 if db or redis is 'error'.
    No structlog logging on this route (high-frequency probe optimisation).

    ConfigDict protected_namespaces=() silences the Pydantic warning for
    the model_loaded field which starts with the reserved model_ prefix.
    """

    model_config = ConfigDict(protected_namespaces=())

    status: str         # 'ok' | 'degraded' | 'error'
    db: str             # 'ok' | 'error'
    redis: str          # 'ok' | 'error'
    model_loaded: bool
    version: str        # settings.MODEL_VERSION
    timestamp: str      # ISO-8601 UTC string
