"""Audit log write utility (Section 3.8, FR-01, FR-05, UC-04).

A single public function — write_audit_log() — is the only way application
code should INSERT into the audit_log table.  UPDATE and DELETE on that table
are prohibited by design (append-only).

Critical invariant: write_audit_log() MUST NEVER raise an exception.  Any
error is caught, logged at ERROR level, and swallowed so that an audit failure
can never cause a route or Celery task to fail.
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

log = structlog.get_logger()


async def write_audit_log(
    db: AsyncSession,
    org_id: uuid.UUID,
    action: str,
    *,
    user_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> None:
    """Insert a row into the ``audit_log`` table.

    All parameters after ``action`` are keyword-only so callers cannot
    accidentally supply them positionally.

    This function is intentionally fire-and-forget: it catches every possible
    exception and logs it at ERROR level without re-raising.  This guarantees
    that audit failures never surface as HTTP 500 errors or Celery task
    failures.

    The row is written with ``db.flush()`` so that it participates in the
    enclosing transaction managed by the caller's ``get_db()`` dependency
    (which commits on success and rolls back on error).  If the surrounding
    transaction later fails, the flush will also be rolled back — this is
    acceptable because a rolled-back action means the auditable event did not
    ultimately occur either.

    Args:
        db:          Active async database session.
        org_id:      UUID of the organisation the event belongs to.
        action:      Event type string — should be a value from
                     :data:`~app.models.audit_log.AUDIT_ACTIONS`.
        user_id:     UUID of the user who triggered the event.  Pass ``None``
                     for system/Celery-initiated events (auto-delete, task_failed,
                     scheduled jobs, etc.).
        target_type: Category of the affected resource (``"email"``, ``"user"``,
                     ``"settings"``, ``"imap_config"``, ``"export_job"``,
                     ``"system"``).  Pass ``None`` for resource-agnostic events.
        target_id:   UUID of the affected record (e.g. the email_id, user_id,
                     or export_job_id).  Pass ``None`` when not applicable.
        detail:      Arbitrary JSON-serialisable payload.  Conventionally used
                     to record before/after values for configuration changes,
                     e.g. ``{"before": {"suspicious": 30}, "after": {"suspicious": 25}}``.
        request_id:  UUID string correlating all DB writes within one HTTP
                     request (D-08 fix).  Sourced from the structlog request
                     middleware and forwarded by route handlers.
        ip_address:  Client IP address string (IPv4 or IPv6) from the
                     ``X-Forwarded-For`` header injected by nginx.
    """
    try:
        entry = AuditLog(
            org_id=org_id,
            action=action,
            user_id=user_id,
            target_type=target_type,
            target_id=target_id,
            detail=detail,
            request_id=request_id,
            ip_address=ip_address,
        )
        db.add(entry)
        await db.flush()
    except Exception as exc:
        log.error(
            "audit_log_write_failed",
            org_id=str(org_id),
            action=action,
            user_id=str(user_id) if user_id else None,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
            request_id=request_id,
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        # Do NOT re-raise — audit failures must never propagate to callers.
