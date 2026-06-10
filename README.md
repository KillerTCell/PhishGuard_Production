# PhishGuard

AI-assisted email threat detection for university IT security teams.

Emails are uploaded (or forwarded) as `.eml` files and run through a five-step pipeline: parse → extract features → classify (Random Forest, F1 = 0.648) → explain (Claude API) → apply outcome. Results appear on a live dashboard with risk scores, explanations, quarantine controls, and bulk-export.

---

## Prerequisites

| Tool | Minimum version | Purpose |
|------|-----------------|---------|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | 4.25 | Container runtime |
| Docker Compose | 2.23 | Multi-container orchestration (bundled with Docker Desktop) |
| Python | 3.12 | Local scripts and tests |
| GNU Make | any | Shorthand targets (`make dev`, `make test`, …) |
| openssl | any | Generating secrets (pre-installed on macOS/Linux; use Git Bash on Windows) |

---

## Quick start

### 1. Clone

```bash
git clone https://github.com/KillerTCell/PhishGuard_Production.git
cd PhishGuard_Production/backend
```

### 2. Create your `.env`

```bash
cp .env.example .env
```

Generate the required secrets and paste them into `.env`:

```bash
# JWT signing secret
openssl rand -hex 32        # → JWT_SECRET

# HMAC secret for quarantine digest one-time tokens
openssl rand -hex 32        # → DIGEST_HMAC_SECRET

# Fernet key for encrypting IMAP passwords at rest
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# → FERNET_KEY
```

Add your API keys:

```
ANTHROPIC_API_KEY=sk-ant-...   # Claude API — explanation engine + AI assistant
RESEND_API_KEY=re_...          # Resend — quarantine digest email delivery
```

The remaining variables have working defaults for local development. See the full table in [`backend/README.md`](backend/README.md#environment-variables).

### 3. Start the stack

```bash
make dev
```

This runs `docker compose up --build` and starts:

- **api** — FastAPI on port 8000 (proxied through nginx)
- **worker** — Celery analysis/digest/export worker
- **beat** — Celery periodic task scheduler
- **postgres** — PostgreSQL 16 on port 5432
- **redis** — Redis 7 on port 6379
- **nginx** — TLS terminator + static file server on ports 80 / 443
- **flower** — Celery monitoring UI on port 5555

Wait for the `api` healthcheck to pass (roughly 15 seconds on first build).

### 4. Run migrations and seed demo data

In a separate terminal:

```bash
make migrate    # alembic upgrade head
make seed       # inserts Demo University + 5 sample emails
```

### 5. Open the app

Open **`PhishGuard.html`** (root of the repo) directly in your browser — it is a self-contained single-page app that talks to the API at `http://localhost`.

API docs (Swagger UI): **http://localhost/api/docs**

---

## Demo credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | `admin@demo.edu` | `PhishGuard2026!` |
| Analyst | `analyst@demo.edu` | `PhishGuard2026!` |

The seed script is idempotent — safe to run multiple times.

---

## Project structure

```
PhishGuard_Production/
├── PhishGuard.html          # Single-page frontend (vanilla JS/HTML/CSS)
├── backend/
│   ├── app/                 # FastAPI application
│   │   ├── routers/         # API route handlers
│   │   ├── models/          # SQLAlchemy ORM models
│   │   ├── schemas/         # Pydantic request/response schemas
│   │   ├── services/        # Business logic (NLP pipeline, email parser, …)
│   │   └── tasks/           # Celery task definitions
│   ├── ml/                  # ML model artefacts (model.pkl, metrics.json)
│   ├── alembic/             # Database migrations
│   ├── nginx/               # nginx config + TLS certs
│   ├── tests/               # pytest test suite
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── Makefile
│   ├── requirements.txt
│   └── .env.example
└── docs/                    # Architecture and deployment notes
```

---

## Common `make` targets

```bash
make dev              # Start full stack (foreground, streaming logs)
make up               # Start full stack (detached)
make down             # Stop and remove containers
make logs             # Tail api/worker/beat logs
make shell            # Open bash shell inside the api container

make test             # pytest + 80 % coverage gate
make test-unit        # Unit tests only
make test-integration # Integration tests only
make lint             # mypy --strict + bandit

make migrate          # Apply pending Alembic migrations
make seed             # Insert demo data
make train            # Retrain Random Forest on ml/train_data.pkl
make evaluate         # F1 quality gate (fails if F1 < 0.85)
```

---

## Required API keys

| Key | Where to get it | Used for |
|-----|----------------|----------|
| `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) | Risk explanations + AI assistant chat |
| `RESEND_API_KEY` | [resend.com](https://resend.com) | Quarantine digest email delivery |

The app runs without these keys — the explanation engine falls back to rule-based templates and digest emails will fail silently.

---

## Deployment

See [`docs/RAILWAY_DEPLOY_MASTER.md`](docs/RAILWAY_DEPLOY_MASTER.md) for Railway deployment instructions.
