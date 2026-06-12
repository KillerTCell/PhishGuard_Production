"""Shared slowapi Limiter instance — imported by main.py and any router that needs rate limiting."""
from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.REDIS_URL,
    default_limits=["200 per minute"],
)
