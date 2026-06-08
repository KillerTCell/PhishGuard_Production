# Model Training Centre

Admin-only feature for accumulating labelled email samples and retraining the Random Forest classifier.

## Overview

The Training Centre lets administrators:
- Add labelled email samples (phishing / safe) via paste, .eml upload, or quarantine export
- Retrain the model on all accumulated samples
- Monitor training history and F1 improvement

## Data is additive — never replaced

Training samples accumulate permanently in the `training_samples` table. Each retrain uses ALL samples ever added for the organisation.

### Why this matters

The Random Forest classifier improves with:
- More samples (quantity)
- More diverse patterns (variety)
- Clean, correctly-labelled examples (quality)

Deleting samples is available per-item (trash icon) for removing mislabelled or duplicate entries only.

### Storage

Each TrainingSample stores:
- `body_text` (TEXT) — the email content
- `label` ('phishing' or 'safe')
- `source` ('manual_paste', 'eml_upload', 'quarantine_export')
- `used_in_training` (BOOLEAN) — set True after each retrain

The `used_in_training` flag is informational only — ALL samples are included in every retrain regardless of this flag. It helps admins see which samples are "new" since last run.

## Navigation

Model Training is under the ADMIN section in the sidebar, visible to admin role only. Analysts cannot access it.

## Retrain process

The retrain Celery task (`app.tasks.training_tasks.retrain_model`):

1. Loads ALL `training_samples` rows for the org (accumulative — no samples deleted)
2. Extracts the 7-element feature vector from each `body_text` using the same NLP extractors as the analysis pipeline
3. Combines real samples with the synthetic base dataset (`ml/train.py` patterns) for robustness when sample counts are small
4. Trains a new `Pipeline(StandardScaler + RandomForestClassifier)`
5. Evaluates macro F1 before and after
6. Bumps the model version (e.g. `rf_v1.0.0` → `rf_v1.0.1`)
7. Saves `ml/model.pkl` and `ml/metrics.json`
8. Clears the in-process model cache so workers pick up the new model immediately
9. Marks all org samples `used_in_training = True`

## API endpoints

All endpoints require admin role (enforced by `require_admin` dependency).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/training/stats` | Sample counts, model version, last F1 |
| GET | `/api/v1/training/samples` | List all samples (latest 200) |
| POST | `/api/v1/training/samples` | Add single pasted sample |
| POST | `/api/v1/training/samples/upload` | Upload .eml files as samples |
| POST | `/api/v1/training/samples/from-quarantine` | Promote confirmed phishing emails |
| DELETE | `/api/v1/training/samples/{id}` | Delete one mislabelled sample |
| POST | `/api/v1/training/retrain` | Trigger async retrain |
| GET | `/api/v1/training/retrain/{task_id}` | Poll retrain progress |

## Database migration

The `training_samples` table is defined in `backend/app/models/training_sample.py`. After deploying, run:

```bash
docker compose exec api alembic upgrade head
```

If Alembic auto-generation is not set up, create the table manually:

```sql
CREATE TABLE training_samples (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organisations(id),
    body_text TEXT NOT NULL,
    label VARCHAR(16) NOT NULL CHECK (label IN ('phishing', 'safe')),
    source VARCHAR(32) NOT NULL DEFAULT 'manual_paste'
        CHECK (source IN ('manual_paste', 'eml_upload', 'quarantine_export')),
    used_in_training BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_training_sample_org_label ON training_samples(org_id, label);
```
