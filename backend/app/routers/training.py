"""Training Centre endpoints (Admin-only).

GET  /training/stats                  -- sample counts, model version, last F1
GET  /training/samples                -- list all samples for this org
POST /training/samples                -- add a single pasted sample
POST /training/samples/upload         -- upload one or more .eml files as samples
POST /training/samples/from-quarantine -- promote quarantined phishing emails to samples
DELETE /training/samples/{id}         -- remove a single mislabelled sample
POST /training/retrain                -- kick off async retrain task
GET  /training/retrain/{task_id}      -- poll retrain task progress
"""
from __future__ import annotations

import email as _email_lib
import json
import uuid
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import CurrentUser, get_db, require_admin
from app.models.training_sample import TrainingSample
from app.schemas.training import (
    AddSampleRequest,
    RetrainResponse,
    RetrainStatusResponse,
    TrainingSampleItem,
    TrainingStatsResponse,
)

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["training"])

# Redis key prefix for retrain task state
_RETRAIN_KEY = "training:retrain:{task_id}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_metrics() -> dict:
    """Read ml/metrics.json produced by the last train/retrain run."""
    import os
    from pathlib import Path
    metrics_path = Path(__file__).resolve().parent.parent.parent / "ml" / "metrics.json"
    if metrics_path.exists():
        try:
            return json.loads(metrics_path.read_text())
        except Exception:
            pass
    return {}


def _eml_body_text(raw_bytes: bytes) -> str:
    """Extract plain-text body from a raw .eml file."""
    try:
        msg = _email_lib.message_from_bytes(raw_bytes)
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode("utf-8", errors="replace").strip()
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                return payload.decode("utf-8", errors="replace").strip()
    except Exception:
        pass
    return raw_bytes.decode("utf-8", errors="replace").strip()


# ---------------------------------------------------------------------------
# GET /training/stats
# ---------------------------------------------------------------------------

@router.get("/training/stats", response_model=TrainingStatsResponse)
async def get_training_stats(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> TrainingStatsResponse:
    total_q = await db.execute(
        select(func.count()).select_from(TrainingSample).where(
            TrainingSample.org_id == current_user.org_id
        )
    )
    total = total_q.scalar_one()

    phishing_q = await db.execute(
        select(func.count()).select_from(TrainingSample).where(
            TrainingSample.org_id == current_user.org_id,
            TrainingSample.label == "phishing",
        )
    )
    phishing = phishing_q.scalar_one()

    new_q = await db.execute(
        select(func.count()).select_from(TrainingSample).where(
            TrainingSample.org_id == current_user.org_id,
            TrainingSample.used_in_training == False,  # noqa: E712
        )
    )
    new_since = new_q.scalar_one()

    metrics = _read_metrics()
    from app.core.config import settings  # noqa: PLC0415
    return TrainingStatsResponse(
        total_samples=total,
        phishing_count=phishing,
        safe_count=total - phishing,
        new_since_last_train=new_since,
        model_version=metrics.get("model_version", settings.MODEL_VERSION),
        last_trained_at=metrics.get("trained_at"),
        last_f1=metrics.get("f1"),
    )


# ---------------------------------------------------------------------------
# GET /training/samples
# ---------------------------------------------------------------------------

@router.get("/training/samples", response_model=list[TrainingSampleItem])
async def list_training_samples(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> list[TrainingSampleItem]:
    result = await db.execute(
        select(TrainingSample)
        .where(TrainingSample.org_id == current_user.org_id)
        .order_by(TrainingSample.created_at.desc())
        .limit(200)
    )
    rows = result.scalars().all()
    return [
        TrainingSampleItem(
            id=r.id,
            label=r.label,
            source=r.source,
            body_preview=(r.body_text[:120] + "…") if len(r.body_text) > 120 else r.body_text,
            used_in_training=r.used_in_training,
            created_at=r.created_at,
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# POST /training/samples  (single paste)
# ---------------------------------------------------------------------------

@router.post("/training/samples", status_code=status.HTTP_201_CREATED)
async def add_training_sample(
    payload: AddSampleRequest,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    # INSERT new row — never replaces existing samples
    sample = TrainingSample(
        org_id=current_user.org_id,
        body_text=payload.body_text,
        label=payload.label,
        source="manual_paste",
        used_in_training=False,
    )
    db.add(sample)
    await db.commit()
    logger.info("training_sample_added", label=payload.label, org_id=str(current_user.org_id))
    return {"id": str(sample.id), "label": payload.label}


# ---------------------------------------------------------------------------
# POST /training/samples/upload  (bulk .eml)
# ---------------------------------------------------------------------------

@router.post("/training/samples/upload", status_code=status.HTTP_201_CREATED)
async def upload_eml_samples(
    label: str = Form(...),
    files: list[UploadFile] = File(...),
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if label not in ("phishing", "safe"):
        raise HTTPException(status_code=422, detail="label must be 'phishing' or 'safe'")
    if not files:
        raise HTTPException(status_code=422, detail="At least one file is required")

    added = 0
    for f in files:
        raw = await f.read()
        body = _eml_body_text(raw)
        if not body.strip():
            continue
        # INSERT each file as a new row — additive, never deletes
        db.add(TrainingSample(
            org_id=current_user.org_id,
            body_text=body,
            label=label,
            source="eml_upload",
            used_in_training=False,
        ))
        added += 1

    await db.commit()
    logger.info("training_samples_uploaded", count=added, label=label, org_id=str(current_user.org_id))
    return {"added": added, "label": label}


# ---------------------------------------------------------------------------
# POST /training/samples/from-quarantine
# ---------------------------------------------------------------------------

@router.post("/training/samples/from-quarantine", status_code=status.HTTP_201_CREATED)
async def samples_from_quarantine(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Promote all confirmed_phishing emails to phishing training samples."""
    from app.models.email import Email  # noqa: PLC0415

    result = await db.execute(
        select(Email).where(
            Email.org_id == current_user.org_id,
            Email.status == "confirmed_phishing",
            Email.body_text.isnot(None),
        )
    )
    emails = result.scalars().all()
    added = 0
    for em in emails:
        body = (em.body_text or "").strip()
        if not body:
            continue
        # INSERT each email as a new training row — additive
        db.add(TrainingSample(
            org_id=current_user.org_id,
            body_text=body,
            label="phishing",
            source="quarantine_export",
            used_in_training=False,
        ))
        added += 1

    await db.commit()
    logger.info("quarantine_samples_promoted", count=added, org_id=str(current_user.org_id))
    return {"added": added, "label": "phishing"}


# ---------------------------------------------------------------------------
# DELETE /training/samples/{id}
# ---------------------------------------------------------------------------

@router.delete("/training/samples/{sample_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_training_sample(
    sample_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Response:
    result = await db.execute(
        select(TrainingSample).where(
            TrainingSample.id == sample_id,
            TrainingSample.org_id == current_user.org_id,
        )
    )
    sample = result.scalar_one_or_none()
    if not sample:
        raise HTTPException(status_code=404, detail="Training sample not found")
    await db.delete(sample)
    await db.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# POST /training/retrain
# ---------------------------------------------------------------------------

@router.post("/training/retrain", response_model=RetrainResponse)
async def trigger_retrain(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> RetrainResponse:
    # Count samples before dispatching
    count_q = await db.execute(
        select(func.count()).select_from(TrainingSample).where(
            TrainingSample.org_id == current_user.org_id
        )
    )
    total = count_q.scalar_one()

    from app.tasks.training_tasks import retrain_model  # noqa: PLC0415

    task = retrain_model.apply_async(
        kwargs={"org_id": str(current_user.org_id)},
        queue="analysis",
    )
    logger.info("retrain_triggered", task_id=task.id, org_id=str(current_user.org_id), sample_count=total)
    return RetrainResponse(task_id=task.id, message=f"Retrain started using {total} samples.")


# ---------------------------------------------------------------------------
# GET /training/retrain/{task_id}
# ---------------------------------------------------------------------------

@router.get("/training/retrain/{task_id}", response_model=RetrainStatusResponse)
async def get_retrain_status(
    task_id: str,
    current_user: CurrentUser = Depends(require_admin),
) -> RetrainStatusResponse:
    from app.tasks.celery_app import celery_app  # noqa: PLC0415

    result = celery_app.AsyncResult(task_id)

    if result.state == "PENDING":
        return RetrainStatusResponse(
            task_id=task_id, status="pending", progress=0,
            f1_before=None, f1_after=None, model_version=None, error=None,
        )
    if result.state == "PROGRESS":
        meta = result.info or {}
        return RetrainStatusResponse(
            task_id=task_id,
            status="running",
            progress=meta.get("progress", 0),
            f1_before=meta.get("f1_before"),
            f1_after=None,
            model_version=None,
            error=None,
        )
    if result.state == "SUCCESS":
        info = result.result or {}
        return RetrainStatusResponse(
            task_id=task_id,
            status="complete",
            progress=100,
            f1_before=info.get("f1_before"),
            f1_after=info.get("f1_after"),
            model_version=info.get("model_version"),
            error=None,
        )
    # FAILURE or REVOKED
    return RetrainStatusResponse(
        task_id=task_id,
        status="failed",
        progress=0,
        f1_before=None,
        f1_after=None,
        model_version=None,
        error=str(result.result) if result.result else "Retrain failed",
    )
