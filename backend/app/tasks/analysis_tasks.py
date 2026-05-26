"""Analysis pipeline Celery tasks (Section 8, FR-02, FR-03, FR-04, UC-02).

Queues:
    analysis -- parse_and_sanitise, extract_features, classify_email,
                generate_explanation, apply_outcome
    imap     -- imap_poll_all_orgs (triggered by Celery Beat every 60 s)

Task chain (Section 5.1 Task 1-5, UC-02):
    parse_and_sanitise(email_id)
        -> extract_features(email_id)
        -> classify_email(email_id)
        -> generate_explanation(email_id)
        -> apply_outcome(email_id)

Each task receives email_id explicitly via .si(str(email_id)) so that the
chain does not depend on return-value propagation.
"""
from __future__ import annotations

import uuid

import structlog
from celery import shared_task

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# FIXED feature order — must match ml/train.py and ml_classifier.py exactly.
# Never reorder without retraining the model.
# ---------------------------------------------------------------------------
_FEATURE_ORDER: list[str] = [
    "urgency_language",
    "credential_request",
    "link_mismatch",
    "impersonation_language",
    "auth_failure",
    "grammar_quality",
    "known_bad_url",
]


# ---------------------------------------------------------------------------
# Shared sync-session factory (one engine per worker process)
# ---------------------------------------------------------------------------


def _make_sync_session():
    """Create a new synchronous SQLAlchemy session bound to the psycopg2 engine.

    Called once per task invocation.  The caller is responsible for
    ``session.commit()`` / ``session.rollback()`` and ``session.close()``.

    Using psycopg2 (sync) is correct for Celery workers — asyncpg only works
    inside a running asyncio event loop.
    """
    from sqlalchemy.orm import sessionmaker  # noqa: PLC0415

    from app.core.database import get_sync_engine  # noqa: PLC0415

    engine = get_sync_engine()
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return Session()


# ---------------------------------------------------------------------------
# Task 1: parse_and_sanitise
# ---------------------------------------------------------------------------


@shared_task(bind=True, max_retries=2, default_retry_delay=10, queue="analysis")
def parse_and_sanitise(self, email_id: str) -> None:
    """Parse raw .eml bytes, sanitise HTML, extract text/headers (FR-02, UC-02 step 2).

    Reads the raw file from ``/tmp/{email_id}.eml`` (written by the upload
    endpoint), parses it with :func:`~app.services.email_parser.parse_eml`,
    sanitises HTML via bleach, and persists all parsed fields back to the
    Email row.  For paste-ingested emails the body_text is already stored.

    Args:
        email_id: UUID string of the Email row to process.
    """
    log.info("task_not_implemented", task="parse_and_sanitise", email_id=email_id)


# ---------------------------------------------------------------------------
# Task 2: extract_features
# ---------------------------------------------------------------------------


@shared_task(bind=True, max_retries=2, default_retry_delay=10, queue="analysis")
def extract_features(self, email_id: str) -> None:
    """Extract NLP and structural features from a parsed email (FR-02, UC-02 step 3).

    Calls :func:`~app.services.nlp_pipeline.extract_all_features` on the
    Email body_text / links / auth fields, then persists one EmailFeature row
    per feature (7 total).  Idempotent: deletes any existing EmailFeature rows
    for this email before inserting fresh ones.

    Args:
        email_id: UUID string of the Email row to process.
    """
    log.info("task_not_implemented", task="extract_features", email_id=email_id)


# ---------------------------------------------------------------------------
# Task 3: classify_email  (fully implemented — Section 5.1 Task 3)
# ---------------------------------------------------------------------------


def _classify_email_inner(email_id: str) -> None:
    """Inner sync worker for classify_email — owns the DB session lifecycle.

    Separated from the Celery task wrapper so that ModelNotFoundError can
    propagate cleanly to the retry handler without the session rollback
    conflicting with Celery's own Retry exception flow.

    Args:
        email_id: UUID string of the Email row to classify.

    Raises:
        ModelNotFoundError: When ml/model.pkl is absent (caller schedules retry).
        Exception: Any other unexpected error (caller logs and re-raises).
    """
    from sqlalchemy import select  # noqa: PLC0415
    from sqlalchemy.dialects.postgresql import insert as pg_insert  # noqa: PLC0415

    from app.core.config import settings  # noqa: PLC0415
    from app.models.analysis_result import AnalysisResult  # noqa: PLC0415
    from app.models.email import Email  # noqa: PLC0415
    from app.models.email_feature import EmailFeature  # noqa: PLC0415
    from app.models.organisation import Organisation  # noqa: PLC0415
    from app.services import ml_classifier  # noqa: PLC0415
    from app.services.ml_classifier import ModelNotFoundError  # noqa: PLC0415 # noqa: F401

    email_uuid = uuid.UUID(email_id)
    session = _make_sync_session()

    try:
        # ── Load email ────────────────────────────────────────────────────────
        email = session.execute(
            select(Email).where(Email.id == email_uuid)
        ).scalar_one_or_none()
        if email is None:
            log.error("classify_email_not_found", email_id=email_id)
            return

        # ── Load org thresholds ───────────────────────────────────────────────
        org = session.execute(
            select(Organisation).where(Organisation.id == email.org_id)
        ).scalar_one_or_none()
        suspicious_threshold: int = org.suspicious_threshold if org else 30
        phishing_threshold: int = org.phishing_threshold if org else 80

        # ── Load NLP features ─────────────────────────────────────────────────
        features = list(
            session.execute(
                select(EmailFeature).where(EmailFeature.email_id == email_uuid)
            ).scalars()
        )

        # ── Build feature vector in FIXED order ───────────────────────────────
        feature_map: dict[str, float] = {
            f.feature_name: float(f.score_contribution) for f in features
        }
        feature_vector: list[float] = [
            feature_map.get(name, 0.0) for name in _FEATURE_ORDER
        ]

        # ── Classify (raises ModelNotFoundError if model.pkl absent) ──────────
        clf_result = ml_classifier.classify(feature_vector)
        risk_score: int = clf_result["risk_score"]

        # ── Apply threshold logic ─────────────────────────────────────────────
        if risk_score < suspicious_threshold:
            classification = "safe"
        elif risk_score < phishing_threshold:
            classification = "suspicious"
        else:
            classification = "phishing"

        # ── Build top-3 features JSON (for AnalysisResult.top_features) ───────
        sorted_feats = sorted(
            features, key=lambda f: f.score_contribution, reverse=True
        )[:3]
        top_features_json: list[dict] = [
            {
                "name": f.feature_name,
                "value": float(f.score_contribution),
                "score_contribution": float(f.score_contribution),
            }
            for f in sorted_feats
        ]

        # ── Upsert AnalysisResult ─────────────────────────────────────────────
        # Uses on_conflict_do_update so re-running the task is idempotent.
        stmt = (
            pg_insert(AnalysisResult.__table__)
            .values(
                email_id=email_uuid,
                classification=classification,
                risk_score=risk_score,
                model_version=settings.MODEL_VERSION,
                threshold_applied_suspicious=suspicious_threshold,
                threshold_applied_phishing=phishing_threshold,
                top_features=top_features_json,
            )
            .on_conflict_do_update(
                constraint="uq_analysis_result_email_id",
                set_={
                    "classification": classification,
                    "risk_score": risk_score,
                    "model_version": settings.MODEL_VERSION,
                    "threshold_applied_suspicious": suspicious_threshold,
                    "threshold_applied_phishing": phishing_threshold,
                    "top_features": top_features_json,
                },
            )
        )
        session.execute(stmt)
        session.commit()

        log.info(
            "classify_email_done",
            email_id=email_id,
            classification=classification,
            risk_score=risk_score,
            n_features=len(features),
        )

    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _mark_email_failed(email_id: str, org_id: uuid.UUID, reason: str) -> None:
    """Set Email.status = 'failed' and write a task_failed audit log entry.

    Best-effort: errors are swallowed and logged so that the audit failure
    never masks the original classification failure.

    Args:
        email_id: UUID string of the Email to mark failed.
        org_id:   Organisation UUID for the audit log row.
        reason:   Short description of the failure cause.
    """
    from sqlalchemy import select, update  # noqa: PLC0415

    from app.models.audit_log import AuditLog  # noqa: PLC0415
    from app.models.email import Email  # noqa: PLC0415

    email_uuid = uuid.UUID(email_id)
    session = _make_sync_session()
    try:
        session.execute(
            update(Email.__table__)
            .where(Email.__table__.c.id == email_uuid)
            .values(status="failed")
        )
        audit_entry = AuditLog(
            org_id=org_id,
            action="task_failed",
            target_type="email",
            target_id=email_uuid,
            detail={"task": "classify_email", "reason": reason},
        )
        session.add(audit_entry)
        session.commit()
    except Exception as exc:
        log.error(
            "mark_email_failed_error",
            email_id=email_id,
            error=str(exc),
        )
        try:
            session.rollback()
        except Exception:
            pass
    finally:
        session.close()


@shared_task(bind=True, max_retries=1, queue="analysis")
def classify_email(self, email_id: str) -> None:
    """Run the Random Forest classifier and record the AnalysisResult (FR-03, UC-02 step 4).

    Reads EmailFeature rows written by extract_features, builds a 7-element
    feature vector, and calls :func:`~app.services.ml_classifier.classify`.
    The result is upserted into analysis_results via
    ``ON CONFLICT DO UPDATE`` so re-runs are idempotent.

    Retry behaviour:
        :class:`~app.services.ml_classifier.ModelNotFoundError` is retried
        once after 30 s (model.pkl may not yet exist on a fresh deploy).
        After max_retries, Email.status is set to ``'failed'`` and a
        ``task_failed`` audit log entry is written.

    Args:
        email_id: UUID string of the Email row to classify.
    """
    from celery.exceptions import MaxRetriesExceededError  # noqa: PLC0415

    from app.models.email import Email  # noqa: PLC0415
    from app.models.organisation import Organisation  # noqa: PLC0415
    from app.services.ml_classifier import ModelNotFoundError  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    try:
        _classify_email_inner(email_id)

    except ModelNotFoundError as model_exc:
        log.warning(
            "classify_email_model_not_found",
            email_id=email_id,
            error=str(model_exc),
        )
        try:
            # self.retry() raises Retry on first attempt, MaxRetriesExceededError
            # on the second — MaxRetriesExceededError is caught below.
            raise self.retry(exc=model_exc, countdown=30)
        except MaxRetriesExceededError:
            log.error(
                "classify_email_max_retries_exceeded",
                email_id=email_id,
            )
            # Resolve org_id for the audit log (best-effort — may be None)
            org_id: uuid.UUID | None = None
            try:
                session = _make_sync_session()
                try:
                    email_row = session.execute(
                        select(Email).where(Email.id == uuid.UUID(email_id))
                    ).scalar_one_or_none()
                    org_id = email_row.org_id if email_row else None
                finally:
                    session.close()
            except Exception as lookup_exc:
                log.error(
                    "classify_email_org_lookup_failed",
                    email_id=email_id,
                    error=str(lookup_exc),
                )

            if org_id is not None:
                _mark_email_failed(email_id, org_id, "ModelNotFoundError")
            else:
                log.error(
                    "classify_email_cannot_mark_failed_no_org",
                    email_id=email_id,
                )

    except Exception as exc:
        log.error(
            "classify_email_failed",
            email_id=email_id,
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        raise


# ---------------------------------------------------------------------------
# Task 4: generate_explanation
# ---------------------------------------------------------------------------


@shared_task(bind=True, max_retries=2, default_retry_delay=30, queue="analysis")
def generate_explanation(self, email_id: str) -> None:
    """Call the Anthropic Claude API to produce a natural-language explanation (FR-04).

    Args:
        email_id: UUID string of the Email row whose classification to explain.
    """
    log.info("task_not_implemented", task="generate_explanation", email_id=email_id)


# ---------------------------------------------------------------------------
# Task 5: apply_outcome
# ---------------------------------------------------------------------------


@shared_task(bind=True, max_retries=2, default_retry_delay=10, queue="analysis")
def apply_outcome(self, email_id: str) -> None:
    """Apply the auto-quarantine or subject-warning outcome after classification (FR-05).

    Args:
        email_id: UUID string of the Email row to act on.
    """
    log.info("task_not_implemented", task="apply_outcome", email_id=email_id)


# ---------------------------------------------------------------------------
# IMAP poller (Beat schedule)
# ---------------------------------------------------------------------------


@shared_task
def imap_poll_all_orgs() -> None:
    """Poll IMAP inboxes for all organisations with an active connector.

    Triggered by Celery Beat every 60 seconds (queue='imap').
    Iterates over organisations where ``connector_status='active'``,
    fetches unseen messages, and dispatches ``parse_and_sanitise`` tasks.
    """
    log.info("task_not_implemented", task="imap_poll_all_orgs")
