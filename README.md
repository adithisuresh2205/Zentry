# SentinelGate

> **Zero-Trust Web Application Security Gateway with Real-Time Threat Detection**

SentinelGate is a security gateway that intercepts, analyzes, risk-scores, and controls incoming HTTP traffic — detecting SQL Injection, XSS, Path Traversal, Command Injection, SSRF, and brute-force attacks before they reach the protected application.

---

## Quick Start (One-Command Docker Setup)

The entire stack (Zero-Trust Gateway, Next.js Tactical UI, PostgreSQL, Redis, and Nginx Reverse Proxy) can be spun up with a single command:

```bash
docker compose up --build
```

### Access URLs

| Service | Access URL | Description |
|---------|------------|-------------|
| **Tactical Dashboard (Frontend)** | [http://localhost:3000](http://localhost:3000) or [https://localhost](https://localhost) | Real-time Zero-Trust SOC Dashboard (Bento UI × Glassmorphism) |
| **API & Gateway (Backend)** | [http://localhost:8000](http://localhost:8000) | FastAPI Security Engine, WAF Detectors & Audit Trail |
| **Interactive API Docs** | [http://localhost:8000/docs](http://localhost:8000/docs) | Swagger OpenAPI Specification |
| **WebSocket Event Stream** | `ws://localhost:8000/ws/security-events` | Real-time live threat and telemetry feed |
| **Gateway Health** | [http://localhost:8000/health](http://localhost:8000/health) | Subsystem healthcheck (DB, Redis, Pipeline) |

### Hot-Reload Development Mode (Optional)

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

---

## Development

### Backend (Python / FastAPI)

```bash
# Install dependencies with uv
pip install uv
uv venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"

# Run database migrations
alembic upgrade head

# Start the gateway
uvicorn backend.main:app --reload --port 8000
```

### Frontend (Next.js)

```bash
cd frontend
npm install
npm run dev          # http://localhost:3000
```

### Running Tests

```bash
# All tests
pytest

# Unit tests only (fast, no DB/Redis needed)
pytest backend/tests/unit/ -v

# Integration tests (requires PostgreSQL + Redis)
pytest backend/tests/integration/ -v

# With coverage report
pytest --cov=backend --cov-report=html
open htmlcov/index.html
```

### Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files     # Run all hooks manually
```

---

## Architecture

```
Internet → Nginx (TLS) → SentinelGate Gateway (FastAPI)
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                         ▼
    Authentication            Rate Limiting           Threat Detection
    (JWT + RBAC)         (Sliding Window / Redis)    (WAF: SQLi, XSS,
                                    │                Path Traversal,
                                    ▼                Cmd Inject, SSRF)
                              Risk Scoring                    │
                           (Multi-signal, 0-100)             │
                                    │◄────────────────────────┘
                                    ▼
                              Policy Engine
                           (ALLOW / BLOCK / ALERT)
                            /              \
                           ▼               ▼
                    Protected App      Audit Log → Dashboard
```

## Phase Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Project Scaffold & DevOps | ✅ Complete |
| 1 | Core Gateway Middleware | ⏳ Next |
| 2 | Authentication & Authorization | ⏳ Upcoming |
| 3 | Rate Limiting & Brute-Force | ⏳ Upcoming |
| 4 | Threat Detection Engine (WAF) | ⏳ Upcoming |
| 5 | Risk Scoring Engine | ⏳ Upcoming |
| 6 | Policy Engine & Security Headers | ⏳ Upcoming |
| 7 | Audit Logging & Database | ⏳ Upcoming |
| 8 | Protected Demo Application | ⏳ Upcoming |
| 9 | Security Dashboard (Frontend) | ⏳ Upcoming |
| 10 | WebSocket Live Feed | ⏳ Upcoming |
| 11 | Testing Strategy | ⏳ Ongoing |
| 12 | Dockerized Deployment | ⏳ Upcoming |

---

## Security Notes

- `SECRET_KEY` must be ≥ 64 hex characters (256 bits). The app **will not start** otherwise.
- Secrets must never be committed. `.env` is in `.gitignore`.
- The `/health` endpoint is restricted to `127.0.0.1` via Nginx.
- The dashboard uses `httpOnly` cookies — tokens are never stored in `localStorage`.
- All audit logs are HMAC-chained for tamper detection.

---

## Project Description

See [`SentinelGate_Project_Description.md`](./SentinelGate_Project_Description.md) for the full specification.
