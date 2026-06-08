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

_N_SAMPLES = 1000  # samples per class (phishing + safe); suspicious uses 400
_RANDOM_SEED = 42


# ---------------------------------------------------------------------------
# Synthetic data generators
# ---------------------------------------------------------------------------


def _generate_phishing_samples(rng: np.random.Generator, n: int) -> np.ndarray:
    """Generate *n* synthetic phishing feature vectors across 5 realistic patterns.

    Args:
        rng: NumPy random generator (seeded for reproducibility).
        n:   Number of samples to generate.

    Returns:
        2-D array of shape (n, 7), dtype float64.
    """
    per_pattern = n // 5
    remainder = n - per_pattern * 5

    # Pattern 1: Urgency + credential request (classic phishing)
    p1 = np.column_stack([
        rng.uniform(0.7, 1.0, per_pattern),                                  # urgency_language
        np.ones(per_pattern),                                                 # credential_request
        rng.uniform(0.5, 1.0, per_pattern),                                  # link_mismatch
        rng.uniform(0.6, 1.0, per_pattern),                                  # impersonation_language
        rng.choice([0.5, 1.0], size=per_pattern, p=[0.4, 0.6]),              # auth_failure
        rng.uniform(0.1, 0.5, per_pattern),                                  # grammar_quality
        rng.choice([0.0, 1.0], size=per_pattern, p=[0.5, 0.5]),              # known_bad_url
    ])
    # Pattern 2: Auth failure + impersonation (spoofed sender)
    p2 = np.column_stack([
        rng.uniform(0.3, 0.8, per_pattern),
        rng.uniform(0.0, 0.5, per_pattern),
        rng.uniform(0.6, 1.0, per_pattern),
        np.ones(per_pattern),
        np.ones(per_pattern),
        rng.uniform(0.2, 0.6, per_pattern),
        rng.choice([0.0, 1.0], size=per_pattern, p=[0.5, 0.5]),
    ])
    # Pattern 3: Known bad URL (malware/phishing link)
    p3 = np.column_stack([
        rng.uniform(0.4, 1.0, per_pattern),
        rng.uniform(0.3, 1.0, per_pattern),
        rng.uniform(0.5, 1.0, per_pattern),
        rng.uniform(0.2, 0.8, per_pattern),
        rng.choice([0.0, 0.5, 1.0], size=per_pattern, p=[0.1, 0.3, 0.6]),
        rng.uniform(0.0, 0.5, per_pattern),
        np.ones(per_pattern),
    ])
    # Pattern 4: High urgency + link mismatch only
    p4 = np.column_stack([
        np.ones(per_pattern),
        rng.uniform(0.0, 0.3, per_pattern),
        np.ones(per_pattern),
        rng.uniform(0.3, 0.7, per_pattern),
        rng.choice([0.0, 0.5], size=per_pattern, p=[0.5, 0.5]),
        rng.uniform(0.3, 0.8, per_pattern),
        rng.choice([0.0, 1.0], size=per_pattern, p=[0.6, 0.4]),
    ])
    # Pattern 5: Multi-signal moderate (real-world sparse phishing)
    p5 = np.column_stack([
        rng.uniform(0.4, 0.8, per_pattern + remainder),
        rng.uniform(0.4, 0.8, per_pattern + remainder),
        rng.uniform(0.3, 0.7, per_pattern + remainder),
        rng.uniform(0.4, 0.8, per_pattern + remainder),
        rng.choice([0.5, 1.0], size=per_pattern + remainder, p=[0.5, 0.5]),
        rng.uniform(0.2, 0.6, per_pattern + remainder),
        rng.choice([0.0, 1.0], size=per_pattern + remainder, p=[0.6, 0.4]),
    ])
    return np.vstack([p1, p2, p3, p4, p5])


def _generate_safe_samples(rng: np.random.Generator, n: int) -> np.ndarray:
    """Generate *n* synthetic safe (legitimate) feature vectors across 4 patterns.

    Args:
        rng: NumPy random generator (seeded for reproducibility).
        n:   Number of samples to generate.

    Returns:
        2-D array of shape (n, 7), dtype float64.
    """
    per_pattern = n // 4
    remainder = n - per_pattern * 4

    # Pattern 1: Fully clean email
    p1 = np.column_stack([
        rng.uniform(0.0, 0.1, per_pattern),
        np.zeros(per_pattern),
        np.zeros(per_pattern),
        rng.uniform(0.0, 0.1, per_pattern),
        np.zeros(per_pattern),
        rng.uniform(0.0, 0.1, per_pattern),
        np.zeros(per_pattern),
    ])
    # Pattern 2: Legitimate marketing (some urgency is fine)
    p2 = np.column_stack([
        rng.uniform(0.1, 0.4, per_pattern),
        np.zeros(per_pattern),
        np.zeros(per_pattern),
        rng.uniform(0.0, 0.2, per_pattern),
        np.zeros(per_pattern),
        rng.uniform(0.0, 0.15, per_pattern),
        np.zeros(per_pattern),
    ])
    # Pattern 3: Internal email with links (no auth configured — all-none)
    p3 = np.column_stack([
        rng.uniform(0.0, 0.2, per_pattern),
        np.zeros(per_pattern),
        rng.uniform(0.0, 0.2, per_pattern),
        np.zeros(per_pattern),
        np.full(per_pattern, 0.5),   # all-none auth — but safe context
        rng.uniform(0.0, 0.1, per_pattern),
        np.zeros(per_pattern),
    ])
    # Pattern 4: Notification email
    p4 = np.column_stack([
        rng.uniform(0.0, 0.3, per_pattern + remainder),
        np.zeros(per_pattern + remainder),
        np.zeros(per_pattern + remainder),
        rng.uniform(0.0, 0.15, per_pattern + remainder),
        rng.choice([0.0, 0.5], size=per_pattern + remainder, p=[0.7, 0.3]),
        rng.uniform(0.0, 0.1, per_pattern + remainder),
        np.zeros(per_pattern + remainder),
    ])
    return np.vstack([p1, p2, p3, p4])


def _generate_suspicious_samples(rng: np.random.Generator, n: int) -> np.ndarray:
    """Generate *n* borderline suspicious feature vectors.

    These represent emails with weak-to-moderate signals — not clean enough
    to be safe, not strong enough to be confirmed phishing.  Training on this
    class teaches the model that auth_failure=0.5 alone is genuinely ambiguous.

    Args:
        rng: NumPy random generator (seeded for reproducibility).
        n:   Number of samples to generate.

    Returns:
        2-D array of shape (n, 7), dtype float64.
    """
    half = n // 2

    # Sub-pattern A: Auth-none only (no body signals — empty-body case)
    pA = np.column_stack([
        rng.uniform(0.0, 0.2, half),
        np.zeros(half),
        rng.uniform(0.0, 0.2, half),
        rng.uniform(0.0, 0.3, half),
        np.full(half, 0.5),           # all-none auth
        rng.uniform(0.0, 0.1, half),
        np.zeros(half),
    ])
    # Sub-pattern B: Moderate multi-signal
    pB = np.column_stack([
        rng.uniform(0.2, 0.6, n - half),
        rng.uniform(0.0, 0.4, n - half),
        rng.uniform(0.0, 0.4, n - half),
        rng.uniform(0.1, 0.4, n - half),
        rng.choice([0.0, 0.5], size=n - half, p=[0.4, 0.6]),
        rng.uniform(0.1, 0.4, n - half),
        np.zeros(n - half),
    ])
    return np.vstack([pA, pB])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Train the RandomForest classifier and save artefacts."""
    rng = np.random.default_rng(_RANDOM_SEED)

    _N_SUSPICIOUS = 400

    # ── Build dataset ─────────────────────────────────────────────────────────
    X_phishing = _generate_phishing_samples(rng, _N_SAMPLES)
    X_safe = _generate_safe_samples(rng, _N_SAMPLES)
    X_suspicious = _generate_suspicious_samples(rng, _N_SUSPICIOUS)
    X = np.vstack([X_phishing, X_safe, X_suspicious])
    y = np.array(
        ["phishing"] * _N_SAMPLES
        + ["safe"] * _N_SAMPLES
        + ["suspicious"] * _N_SUSPICIOUS
    )

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
                    n_estimators=200,
                    class_weight="balanced",
                    min_samples_leaf=2,
                    max_features="sqrt",
                    random_state=_RANDOM_SEED,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    pipeline.fit(X_train, y_train)

    # ── Evaluate ──────────────────────────────────────────────────────────────
    y_pred = pipeline.predict(X_test)
    f1 = float(f1_score(y_test, y_pred, average="macro"))
    precision = float(precision_score(y_test, y_pred, average="macro"))
    recall = float(recall_score(y_test, y_pred, average="macro"))

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
