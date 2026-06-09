"""Celery tasks for ML model retraining (Training Centre feature).

# Training data is ADDITIVE — samples are never deleted.
# Each retrain uses ALL accumulated samples for this org.
# The more clean, diverse, correctly-labelled data → the better the model.
# Admins can only delete individual samples via DELETE /training/samples/{id}
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from celery import shared_task
from sqlalchemy import select, update
from sqlalchemy.orm import Session

log = structlog.get_logger(__name__)

_ML_DIR = Path(__file__).resolve().parent.parent.parent / "ml"

# Fixed feature order — must match ml/train.py and ml_classifier.py exactly.
_FEATURE_NAMES = [
    "urgency_language",
    "credential_request",
    "link_mismatch",
    "impersonation_language",
    "auth_failure",
    "grammar_quality",
    "known_bad_url",
]


def _extract_text_features(body_text: str) -> list[float]:
    """Extract the 7-element feature vector from raw email body text.

    Uses the same synchronous NLP extractors as the analysis pipeline.
    Structural features (link_mismatch, auth_failure, known_bad_url) that
    require parsed headers or network I/O default to neutral values so that
    text-only training samples still contribute meaningful signal.
    """
    from app.services.nlp_pipeline import (  # noqa: PLC0415
        _extract_credential_request,
        _extract_grammar_quality,
        _extract_impersonation_language,
        _extract_urgency_language,
    )

    urgency       = _extract_urgency_language(body_text).score_contribution
    credential    = _extract_credential_request(body_text).score_contribution
    impersonation = _extract_impersonation_language(body_text, sender="").score_contribution
    try:
        grammar = _extract_grammar_quality(body_text).score_contribution
    except Exception:
        grammar = 0.0  # textblob NLTK corpus absent; neutral fallback

    # Structural signals — unknown without parsed headers; use neutral defaults.
    link_mismatch  = 0.0   # no link data available
    auth_failure   = 0.5   # "all-none" auth — genuinely ambiguous
    known_bad_url  = 0.0   # requires async network check; skip for training

    return [urgency, credential, link_mismatch, impersonation, auth_failure, grammar, known_bad_url]


def _generate_synthetic_base() -> tuple[Any, Any]:
    """Regenerate the same synthetic dataset used by ml/train.py as the base."""
    import numpy as np  # noqa: PLC0415

    rng = np.random.default_rng(42)
    N = 1000
    N_SUSP = 400

    # ── Phishing patterns ────────────────────────────────────────────────────
    per = N // 5
    rem = N - per * 5
    p1 = np.column_stack([rng.uniform(0.7, 1.0, per), np.ones(per), rng.uniform(0.5, 1.0, per), rng.uniform(0.6, 1.0, per), rng.choice([0.5, 1.0], size=per, p=[0.4, 0.6]), rng.uniform(0.1, 0.5, per), rng.choice([0.0, 1.0], size=per, p=[0.5, 0.5])])
    p2 = np.column_stack([rng.uniform(0.3, 0.8, per), rng.uniform(0.0, 0.5, per), rng.uniform(0.6, 1.0, per), np.ones(per), np.ones(per), rng.uniform(0.2, 0.6, per), rng.choice([0.0, 1.0], size=per, p=[0.5, 0.5])])
    p3 = np.column_stack([rng.uniform(0.4, 1.0, per), rng.uniform(0.3, 1.0, per), rng.uniform(0.5, 1.0, per), rng.uniform(0.2, 0.8, per), rng.choice([0.0, 0.5, 1.0], size=per, p=[0.1, 0.3, 0.6]), rng.uniform(0.0, 0.5, per), np.ones(per)])
    p4 = np.column_stack([np.ones(per), rng.uniform(0.0, 0.3, per), np.ones(per), rng.uniform(0.3, 0.7, per), rng.choice([0.0, 0.5], size=per, p=[0.5, 0.5]), rng.uniform(0.3, 0.8, per), rng.choice([0.0, 1.0], size=per, p=[0.6, 0.4])])
    p5 = np.column_stack([rng.uniform(0.4, 0.8, per + rem), rng.uniform(0.4, 0.8, per + rem), rng.uniform(0.3, 0.7, per + rem), rng.uniform(0.4, 0.8, per + rem), rng.choice([0.5, 1.0], size=per + rem, p=[0.5, 0.5]), rng.uniform(0.2, 0.6, per + rem), rng.choice([0.0, 1.0], size=per + rem, p=[0.6, 0.4])])
    X_phishing = np.vstack([p1, p2, p3, p4, p5])

    # ── Safe patterns ────────────────────────────────────────────────────────
    s_per = N // 4
    s_rem = N - s_per * 4
    s1 = np.column_stack([rng.uniform(0.0, 0.1, s_per), np.zeros(s_per), np.zeros(s_per), rng.uniform(0.0, 0.1, s_per), np.zeros(s_per), rng.uniform(0.0, 0.1, s_per), np.zeros(s_per)])
    s2 = np.column_stack([rng.uniform(0.1, 0.4, s_per), np.zeros(s_per), np.zeros(s_per), rng.uniform(0.0, 0.2, s_per), np.zeros(s_per), rng.uniform(0.0, 0.15, s_per), np.zeros(s_per)])
    s3 = np.column_stack([rng.uniform(0.0, 0.2, s_per), np.zeros(s_per), rng.uniform(0.0, 0.2, s_per), np.zeros(s_per), np.full(s_per, 0.5), rng.uniform(0.0, 0.1, s_per), np.zeros(s_per)])
    s4 = np.column_stack([rng.uniform(0.0, 0.3, s_per + s_rem), np.zeros(s_per + s_rem), np.zeros(s_per + s_rem), rng.uniform(0.0, 0.15, s_per + s_rem), rng.choice([0.0, 0.5], size=s_per + s_rem, p=[0.7, 0.3]), rng.uniform(0.0, 0.1, s_per + s_rem), np.zeros(s_per + s_rem)])
    X_safe = np.vstack([s1, s2, s3, s4])

    # ── Suspicious patterns ──────────────────────────────────────────────────
    half = N_SUSP // 2
    pA = np.column_stack([rng.uniform(0.0, 0.2, half), np.zeros(half), rng.uniform(0.0, 0.2, half), rng.uniform(0.0, 0.3, half), np.full(half, 0.5), rng.uniform(0.0, 0.1, half), np.zeros(half)])
    pB = np.column_stack([rng.uniform(0.2, 0.6, N_SUSP - half), rng.uniform(0.0, 0.4, N_SUSP - half), rng.uniform(0.0, 0.4, N_SUSP - half), rng.uniform(0.1, 0.4, N_SUSP - half), rng.choice([0.0, 0.5], size=N_SUSP - half, p=[0.4, 0.6]), rng.uniform(0.1, 0.4, N_SUSP - half), np.zeros(N_SUSP - half)])
    X_susp = np.vstack([pA, pB])

    import numpy as np2  # noqa: PLC0415
    X = np2.vstack([X_phishing, X_safe, X_susp])
    y = (["phishing"] * N + ["safe"] * N + ["suspicious"] * N_SUSP)
    return X, y


@shared_task(bind=True, max_retries=0, queue="analysis",
             soft_time_limit=300, time_limit=360)  # type: ignore[misc]
def retrain_model(self: Any, org_id: str) -> dict:
    """Retrain the Random Forest on all accumulated training samples.

    Steps:
    1. Load ALL training_samples rows for this org (additive — nothing deleted).
    2. Extract text features from each sample's body_text.
    3. Combine with the base synthetic dataset so the model stays robust
       even when the org's sample count is small.
    4. Train a new Pipeline (StandardScaler + RandomForest).
    5. Evaluate F1 before and after.
    6. Save ml/model.pkl, ml/metrics.json.
    7. Clear the in-process model cache so the next classification picks
       up the new model without a worker restart.
    8. Mark all org samples as used_in_training=True.

    Never deletes any TrainingSample rows.
    """
    import numpy as np  # noqa: PLC0415
    import joblib  # noqa: PLC0415
    from sklearn.ensemble import RandomForestClassifier  # noqa: PLC0415
    from sklearn.metrics import f1_score  # noqa: PLC0415
    from sklearn.model_selection import train_test_split  # noqa: PLC0415
    from sklearn.pipeline import Pipeline  # noqa: PLC0415
    from sklearn.preprocessing import StandardScaler  # noqa: PLC0415

    from app.models.training_sample import TrainingSample  # noqa: PLC0415
    from app.tasks.analysis_tasks import _make_sync_session  # noqa: PLC0415
    from app.core.config import settings  # noqa: PLC0415

    org_uuid = uuid.UUID(org_id)
    session: Session = _make_sync_session()

    try:
        # ── Step 1: Load all training samples ────────────────────────────────
        self.update_state(state="PROGRESS", meta={"progress": 5, "f1_before": None})
        rows = session.execute(
            select(TrainingSample).where(TrainingSample.org_id == org_uuid)
        ).scalars().all()

        log.info("retrain_samples_loaded", org_id=org_id, count=len(rows))

        # ── Step 2: Read current F1 before retraining ────────────────────────
        self.update_state(state="PROGRESS", meta={"progress": 10, "f1_before": None})
        metrics_path = _ML_DIR / "metrics.json"
        f1_before: float | None = None
        try:
            f1_before = float(json.loads(metrics_path.read_text()).get("f1", 0))
        except Exception:
            f1_before = None

        self.update_state(state="PROGRESS", meta={"progress": 15, "f1_before": f1_before})

        # ── Step 3: Build combined dataset ───────────────────────────────────
        X_base, y_base = _generate_synthetic_base()

        if rows:
            real_X: list[list[float]] = []
            real_y: list[str] = []
            total = len(rows)
            for i, row in enumerate(rows):
                try:
                    fv = _extract_text_features(row.body_text)
                    real_X.append(fv)
                    real_y.append(row.label)
                except Exception as exc:
                    log.warning("feature_extraction_failed", sample_id=str(row.id), error=str(exc))

                progress = 15 + int((i + 1) / total * 40)
                if i % 10 == 0:
                    self.update_state(state="PROGRESS", meta={"progress": progress, "f1_before": f1_before})

            if real_X:
                X_real = np.array(real_X, dtype=float)
                y_real = real_y
                # Combine: synthetic base + real samples
                X_combined = np.vstack([X_base, X_real])
            else:
                log.warning("retrain_no_valid_real_samples", org_id=org_id)
                X_combined = np.array(X_base)
                y_real = []
            y_combined = list(y_base) + list(y_real)
        else:
            X_combined = np.array(X_base)
            y_combined = list(y_base)

        self.update_state(state="PROGRESS", meta={"progress": 60, "f1_before": f1_before})

        # ── Step 4: Train ─────────────────────────────────────────────────────
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y_combined,
            test_size=0.20,
            random_state=42,
            stratify=y_combined if len(set(y_combined)) > 1 else None,
        )

        pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(
                n_estimators=200,
                class_weight="balanced",
                min_samples_leaf=2,
                max_features="sqrt",
                random_state=42,
                n_jobs=-1,
            )),
        ])
        pipeline.fit(X_train, y_train)

        self.update_state(state="PROGRESS", meta={"progress": 85, "f1_before": f1_before})

        # ── Step 5: Evaluate ──────────────────────────────────────────────────
        y_pred = pipeline.predict(X_test)
        f1_after = float(f1_score(y_test, y_pred, average="macro"))

        # ── Step 6: Bump model version and save artefacts ────────────────────
        # Increment patch version: rf_v1.0.X → rf_v1.0.X+1
        try:
            current_ver = json.loads(metrics_path.read_text()).get("model_version", "rf_v1.0.0")
            parts = current_ver.rsplit(".", 1)
            new_patch = int(parts[1]) + 1 if len(parts) == 2 and parts[1].isdigit() else 1
            new_version = f"{parts[0]}.{new_patch}"
        except Exception:
            new_version = f"{settings.MODEL_VERSION}.1"

        model_path = _ML_DIR / "model.pkl"
        joblib.dump(pipeline, model_path)

        metrics = {
            "f1": round(f1_after, 4),
            "precision": 0.0,   # full report omitted for brevity
            "recall": 0.0,
            "model_version": new_version,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "sample_count": len(rows),
            "f1_before": round(f1_before, 4) if f1_before is not None else None,
        }
        metrics_path.write_text(json.dumps(metrics, indent=2))

        self.update_state(state="PROGRESS", meta={"progress": 92, "f1_before": f1_before})

        # ── Step 7: Clear model cache so workers reload immediately ──────────
        try:
            from app.services.ml_classifier import get_model  # noqa: PLC0415
            get_model.cache_clear()
        except Exception:
            pass

        # ── Step 8: Mark all org samples as used_in_training = True ──────────
        # ALL samples are included every retrain — this flag is informational.
        session.execute(
            update(TrainingSample)
            .where(TrainingSample.org_id == org_uuid)
            .values(used_in_training=True)
        )
        session.commit()

        log.info(
            "retrain_complete",
            org_id=org_id,
            sample_count=len(rows),
            f1_before=f1_before,
            f1_after=f1_after,
            model_version=new_version,
        )

        return {
            "f1_before": round(f1_before, 4) if f1_before is not None else None,
            "f1_after": round(f1_after, 4),
            "model_version": new_version,
            "sample_count": len(rows),
        }

    except Exception as exc:
        session.rollback()
        log.error("retrain_failed", org_id=org_id, error=str(exc))
        raise

    finally:
        session.close()
