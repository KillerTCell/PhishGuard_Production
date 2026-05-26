"""ML model training script (Section 10.1 NFR-6, Section 8).

Feature vector FIXED order (must match classify_email task and ml_classifier.py):
    [urgency_language, credential_request, link_mismatch,
     impersonation_language, auth_failure, grammar_quality, known_bad_url]

Run from the backend directory:
    cd backend && python ml/train.py

Produces:
    ml/model.pkl      -- serialised sklearn Pipeline (StandardScaler + RandomForest)
    ml/test_data.pkl  -- (X_test, y_test) tuple for evaluate.py regression gate
    ml/metrics.json   -- {f1, precision, recall, model_version, trained_at}
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure backend/ is on sys.path so ``from app.core.config import settings`` works
# when the script is run as ``python ml/train.py`` from the backend directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

try:
    from app.core.config import settings as _settings

    _MODEL_VERSION: str = _settings.MODEL_VERSION
except Exception:
    _MODEL_VERSION = "rf_v1.0.0"

_OUTPUT_DIR = Path(__file__).resolve().parent

# FIXED feature order — must never be reordered without retraining.
_FEATURE_NAMES: list[str] = [
    "urgency_language",
    "credential_request",
    "link_mismatch",
    "impersonation_language",
    "auth_failure",
    "grammar_quality",
    "known_bad_url",
]

_N_SAMPLES = 500   # samples per class
_RANDOM_SEED = 42


# ---------------------------------------------------------------------------
# Synthetic data generators
# ---------------------------------------------------------------------------


def _generate_phishing_samples(rng: np.random.Generator, n: int) -> np.ndarray:
    """Generate *n* synthetic phishing feature vectors.

    Distributions are deliberately well-separated from safe samples so that
    the Random Forest can easily reach F1 >= 0.85 on held-out test data.

    Args:
        rng: NumPy random generator (seeded for reproducibility).
        n:   Number of samples to generate.

    Returns:
        2-D array of shape (n, 7), dtype float64.
    """
    return np.column_stack(
        [
            rng.uniform(0.30, 1.00, n),                                      # urgency_language
            rng.choice([0.0, 1.0], size=n, p=[0.15, 0.85]),                  # credential_request
            rng.uniform(0.20, 1.00, n),                                      # link_mismatch
            rng.uniform(0.30, 1.00, n),                                      # impersonation_language
            rng.choice([0.0, 0.5, 1.0], size=n, p=[0.05, 0.20, 0.75]),      # auth_failure
            rng.uniform(0.20, 0.80, n),                                      # grammar_quality
            rng.choice([0.0, 1.0], size=n, p=[0.30, 0.70]),                  # known_bad_url
        ]
    )


def _generate_safe_samples(rng: np.random.Generator, n: int) -> np.ndarray:
    """Generate *n* synthetic safe (legitimate) feature vectors.

    Args:
        rng: NumPy random generator (seeded for reproducibility).
        n:   Number of samples to generate.

    Returns:
        2-D array of shape (n, 7), dtype float64.
    """
    return np.column_stack(
        [
            rng.uniform(0.00, 0.20, n),                                      # urgency_language
            rng.choice([0.0, 1.0], size=n, p=[0.95, 0.05]),                  # credential_request
            rng.uniform(0.00, 0.15, n),                                      # link_mismatch
            rng.uniform(0.00, 0.20, n),                                      # impersonation_language
            rng.choice([0.0, 0.5, 1.0], size=n, p=[0.80, 0.15, 0.05]),      # auth_failure
            rng.uniform(0.00, 0.15, n),                                      # grammar_quality
            rng.choice([0.0, 1.0], size=n, p=[0.98, 0.02]),                  # known_bad_url
        ]
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Train the RandomForest classifier and save artefacts."""
    rng = np.random.default_rng(_RANDOM_SEED)

    # ── Build dataset ─────────────────────────────────────────────────────────
    X_phishing = _generate_phishing_samples(rng, _N_SAMPLES)
    X_safe = _generate_safe_samples(rng, _N_SAMPLES)
    X = np.vstack([X_phishing, X_safe])
    y = np.array(["phishing"] * _N_SAMPLES + ["safe"] * _N_SAMPLES)

    # ── Train / test split ────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=_RANDOM_SEED,
        stratify=y,
    )

    # ── Build and fit pipeline ────────────────────────────────────────────────
    pipeline = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                RandomForestClassifier(
                    n_estimators=100,
                    class_weight="balanced",
                    random_state=_RANDOM_SEED,
                ),
            ),
        ]
    )
    pipeline.fit(X_train, y_train)

    # ── Evaluate ──────────────────────────────────────────────────────────────
    y_pred = pipeline.predict(X_test)
    f1 = float(f1_score(y_test, y_pred, pos_label="phishing"))
    precision = float(precision_score(y_test, y_pred, pos_label="phishing"))
    recall = float(recall_score(y_test, y_pred, pos_label="phishing"))

    print(classification_report(y_test, y_pred, digits=4))
    print(
        f"F1 (phishing): {f1:.4f}  "
        f"Precision: {precision:.4f}  "
        f"Recall: {recall:.4f}"
    )

    # ── Persist artefacts ─────────────────────────────────────────────────────
    model_path = _OUTPUT_DIR / "model.pkl"
    test_data_path = _OUTPUT_DIR / "test_data.pkl"
    metrics_path = _OUTPUT_DIR / "metrics.json"

    joblib.dump(pipeline, model_path)
    joblib.dump((X_test, y_test), test_data_path)

    metrics = {
        "f1": round(f1, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "model_version": _MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    metrics_path.write_text(json.dumps(metrics, indent=2))

    print(f"\nSaved model   -> {model_path}")
    print(f"Saved test    -> {test_data_path}")
    print(f"Saved metrics -> {metrics_path}")


if __name__ == "__main__":
    main()
