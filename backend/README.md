# PhishGuard Backend — Quick Start

PhishGuard is an AI-assisted email threat detection system built for university IT
security teams. The backend exposes a REST API (FastAPI + PostgreSQL + Redis + Celery)
that processes uploaded `.eml` files through a five-step ML pipeline: parse → extract
features → classify (Random Forest) → generate explanation (Claude API) → apply outcome.

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Docker Desktop | ≥ 4.25 | Container runtime for all services |
| Docker Compose | ≥ 2.23 | Multi-container orchestration |
| Python | 3.12 | Local development / scripts |
| GNU Make | any | Convenience targets (`make dev`, `make test`, …) |

---

## Setup

```bash
git clone <repo-url>
cd phishguard/backend

# Copy the environment template and fill in secrets
cp .env.example .env
```

Edit `.env` and provide values for the required secrets:

```bash
# Generate JWT secret (minimum 32 chars)
openssl rand -hex 32   # → JWT_SECRET

# Generate HMAC secret for digest one-time tokens
openssl rand -hex 32   # → DIGEST_HMAC_SECRET

# Generate Fernet key for encrypting IMAP passwords at rest
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
# → FERNET_KEY
```

Then add your API keys:

```
ANTHROPIC_API_KEY=sk-ant-...   # Claude API — FR-04 explanation engine
RESEND_API_KEY=re_...          # Resend — FR-06 quarantine digest email
```

Start all services (API, Celery worker, Celery Beat, PostgreSQL, Redis, nginx):

```bash
make dev        # docker compose up --build (foreground, streaming logs)
```

Run database migrations and seed demo data:

```bash
make migrate    # alembic upgrade head
make seed       # inserts Demo University + 5 sample emails
```

The Swagger UI is available at **http://localhost/api/docs** once the stack is running.

---

## Demo credentials (after `make seed`)

| Role | Email | Password |
|------|-------|----------|
| Admin | `admin@demo.edu` | `PhishGuard2026!` |
| Analyst | `analyst@demo.edu` | `PhishGuard2026!` |

The seed script is idempotent — running it twice has no effect.

---

## Environment variables

All 15 variables are read by `app/core/config.py` (Pydantic `BaseSettings`).
The `.env.example` file contains generation commands for every secret.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | ✅ | — | PostgreSQL async DSN (`postgresql+asyncpg://…`) |
| `REDIS_URL` | ✅ | — | Redis DSN — SSE Pub/Sub, JWT blacklist, rate-limit counters |
| `CELERY_BROKER_URL` | ✅ | — | Celery broker DSN (typically same Redis as `REDIS_URL`) |
| `CELERY_RESULT_BACKEND` | | `""` | Celery result backend DSN (separate Redis DB index) |
| `JWT_SECRET` | ✅ | — | HS256 signing secret — minimum 32 characters (NFR-2) |
| `JWT_EXPIRE_HOURS` | | `8` | Access token lifetime in hours |
| `DIGEST_HMAC_SECRET` | ✅ | — | HMAC-SHA256 key for quarantine digest one-time tokens |
| `FERNET_KEY` | ✅ | — | Fernet key for encrypting IMAP passwords at rest |
| `ANTHROPIC_API_KEY` | ✅ | — | Anthropic Claude API key — explanation engine + AI assistant |
| `RESEND_API_KEY` | ✅ | — | Resend API key — quarantine digest email delivery |
| `CORS_ORIGINS` | | `http://localhost:3000,…` | Comma-separated allowed CORS origins |
| `MODEL_VERSION` | | `rf_v1.0.0` | ML model version tag — must match `ml/model.pkl` |
| `FORWARDING_DOMAIN` | | `phishguard.app` | Domain for forwarding inbox slugs |
| `DEMO_SAMPLE_EML` | | `""` | Raw `.eml` content for the Load Demo Sample button |
| `EXPORT_VOLUME_PATH` | | `/mnt/exports` | Absolute path to the CSV export Docker volume |

---

## Architecture — five-step analysis pipeline

```
POST /emails/upload (.eml)
        │
        ▼
① parse_and_sanitise   — decode MIME, bleach HTML, extract headers/links
        │
        ▼
② extract_features     — 7 NLP/heuristic features (urgency, link mismatch,
        │                  auth failure, impersonation, …) + PhishTank lookup
        ▼
③ classify_email       — Random Forest pipeline (sklearn) scores 0–100;
        │                  thresholds: suspicious ≥ 30, phishing ≥ 80
        ▼
④ generate_explanation — Claude API 2–3 sentence human-readable explanation;
        │                  falls back to rule-based templates on API error
        ▼
⑤ apply_outcome        — sets email.status (delivered/flagged/quarantined),
                          writes analysis_results, fires SSE event to dashboard
```

Each step is a Celery task on the `analysis` queue. The chain is dispatched
asynchronously on upload so the HTTP response returns 202 immediately.

---

## Running tests

```bash
make test               # pytest + 80 % coverage gate (all tests)
make test-unit          # unit tests only (no integration marker)
make test-integration   # integration tests only
make test-nlp           # NLP pipeline tests with dedicated coverage report
```

---

## Code quality

```bash
make lint       # mypy --strict app/ && bandit -r app/ -ll
make typecheck  # mypy --strict only
make security   # bandit only
```

---

## ML pipeline

```bash
make train      # train Random Forest on ml/train_data.pkl → ml/model.pkl
make evaluate   # F1 quality gate — exits 1 if F1 < 0.85 or regression > 0.02
```

The current model achieves **F1 = 1.00** on the held-out test set
(see `ml/metrics.json`).

---

## Deployment

See `DEPLOY.md` for production deployment instructions including:

- Docker Compose production overrides
- nginx TLS certificate provisioning (Let's Encrypt / self-signed)
- Secrets management (Docker secrets vs `.env`)
- Celery worker scaling
- PostgreSQL backup strategy
- Data retention configuration
