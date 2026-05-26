"""ML model evaluation script — F1 quality gate (Section 10.1 NFR-6, Section 8).

Run after training:
    cd backend && python ml/evaluate.py

Exits with code 1 if any gate fails:
    - Absolute gate:   F1 < 0.85
    - Regression gate: new_f1 < existing_f1 - 0.02

On pass: prints classification report and updates ml/metrics.json with
``evaluated_at`` timestamp.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure backend/ is on sys.path so app imports work when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score

_DIR = Path(__file__).resolve().parent

_F1_THRESHOLD: float = 0.85
_REGRESSION_TOLERANCE: float = 0.02


def main() -> None:
    """Evaluate the trained model against quality gates and update metrics.json."""
    model_path = _DIR / "model.pkl"
    test_data_path = _DIR / "test_data.pkl"
    metrics_path = _DIR / "metrics.json"

    # ── Guard: artefacts must exist ───────────────────────────────────────────
    if not model_path.exists():
        print(
            f"ERROR: {model_path} not found. Run 'python ml/train.py' first.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not test_data_path.exists():
        print(
            f"ERROR: {test_data_path} not found. Run 'python ml/train.py' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Load artefacts ────────────────────────────────────────────────────────
    pipeline = joblib.load(model_path)
    X_test, y_test = joblib.load(test_data_path)

    # ── Compute metrics ───────────────────────────────────────────────────────
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

    # ── Quality gates ─────────────────────────────────────────────────────────
    failed = False

    # Absolute gate
    if f1 < _F1_THRESHOLD:
        print(
            f"\nFAIL [absolute gate]: F1 {f1:.4f} < threshold {_F1_THRESHOLD}",
            file=sys.stderr,
        )
        failed = True

    # Regression gate — compare against the baseline in metrics.json (if present)
    existing_f1: float | None = None
    existing_trained_at: str = ""
    if metrics_path.exists():
        try:
            existing_metrics = json.loads(metrics_path.read_text())
            existing_f1 = float(existing_metrics.get("f1", 0.0))
            existing_trained_at = str(existing_metrics.get("trained_at", ""))
        except Exception as exc:
            print(f"WARNING: could not parse {metrics_path}: {exc}", file=sys.stderr)

    if existing_f1 is not None:
        min_allowed = existing_f1 - _REGRESSION_TOLERANCE
        if f1 < min_allowed:
            print(
                f"\nFAIL [regression gate]: new F1 {f1:.4f} < "
                f"baseline {existing_f1:.4f} - {_REGRESSION_TOLERANCE} = {min_allowed:.4f}",
                file=sys.stderr,
            )
            failed = True

    if failed:
        sys.exit(1)

    print("\nPASS: all quality gates satisfied.")

    # ── Update metrics.json ───────────────────────────────────────────────────
    try:
        from app.core.config import settings as _settings  # noqa: PLC0415

        model_version: str = _settings.MODEL_VERSION
    except Exception:
        model_version = "rf_v1.0.0"

    updated_metrics = {
        "f1": round(f1, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "model_version": model_version,
        "trained_at": existing_trained_at or datetime.now(timezone.utc).isoformat(),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
    metrics_path.write_text(json.dumps(updated_metrics, indent=2))
    print(f"Updated metrics -> {metrics_path}")


if __name__ == "__main__":
    main()
