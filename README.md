# SentinelGraph-AI

SentinelGraph-AI is an academic mini-SIEM that collects security logs, evaluates detection rules, manages alerts, and explores relationships between indicators and assets.

## Architecture

- **Frontend:** React 19, TypeScript, Vite, and Nginx.
- **Backend:** FastAPI with JWT authentication and role-based API dependencies.
- **MongoDB:** Stores users, servers, rules, logs, alerts, analyses, and audit records as operational documents.
- **Neo4j:** Models IP, user, server, event, and alert relationships for graph investigation.
- **Ollama:** Optional local model endpoint for generated analyses. If it is unavailable, the backend returns a clearly marked deterministic rule-based advisory.

MongoDB is the primary record store because the application ingests and filters varied event documents. Neo4j complements it with relationship traversals that are awkward to express as document queries. This project is an educational prototype, not a certified or production-hardened SIEM.

## Features

- Login with Administrator, Security Analyst, and Viewer roles.
- Normalized log ingestion, filters, pagination, and per-record integrity verification.
- Six detection families: brute force, unusual IP, off-hours access, privilege escalation, distributed brute force, and suspicious patterns.
- Alert review, notes, evidence lookup, and status updates.
- Server inventory and editable detection-rule settings.
- Dashboard analytics and Neo4j topology, attacker, blast-radius, and attack-path views.
- Ollama analysis/chat with deterministic offline fallback.
- Seeded demo users, assets, rules, and sample security telemetry on a new database.

The seeded sample telemetry is illustrative data; it is not live threat intelligence.

## Prerequisites

- Windows 11 with Docker Desktop installed and running.
- Docker Compose v2 (bundled with current Docker Desktop).
- At least 4 GB of available RAM for the containers; more is recommended.
- Ollama is optional. To use it, run Ollama on the host and pull the model configured in `.env`.

Python and Node.js do not need to be installed on Windows; Docker builds both application services.

## One-command startup

From the extracted project folder, open PowerShell and run:

```powershell
.\start-project.bat
```

On first start, the script creates `.env` from `.env.example` and generates random local Neo4j, JWT, and seeded-account passwords. Keep `.env` private; it is excluded from Git. MongoDB is published only on loopback for this academic single-machine setup; it is not configured for remote or production use. The script then validates Compose, builds the services, waits for their health checks, and prints service status.

### URLs

- Web application: <http://localhost:3000>
- FastAPI documentation: <http://localhost:8000/docs>
- Backend health: <http://localhost:8000/health>
- Neo4j Browser: <http://localhost:7474>

Neo4j Browser username is `neo4j`; its password is the `NEO4J_PASSWORD` value in `.env`. Service ports bind to loopback by default; optional port overrides are in `.env`.

When upgrading a database created by the earlier project version, the named MongoDB and Neo4j volumes are retained. Neo4j does not rotate the password in an already-initialized data volume when `NEO4J_PASSWORD` changes. Before starting with an existing volume, set that variable in `.env` to the password already stored by that database; do not reset volumes if you need to preserve existing data.

## First administrator login

The seeded administrator username is `admin`. Its random initial password is stored as `SEED_ADMIN_PASSWORD` in the local `.env` file. The same file contains the initial `analyst` and `viewer` passwords. The login form does not prefill credentials.

Seed accounts are created only when the users collection is empty. Existing database volumes keep their existing user accounts and passwords; startup does not reset them.

## Stop and reset

Stop the services while preserving database volumes:

```powershell
.\stop-project.bat
```

To permanently delete MongoDB and Neo4j data, run:

```powershell
.\reset-project.bat
```

The reset script requires typing `DELETE` before it removes volumes. Use it only when you intentionally want to discard all persisted project data.

## API overview

All versioned routes are under `/api/v1`. The interactive OpenAPI reference is at `/docs` when the backend is running.

- `/auth`: login, profile, and administrator user management.
- `/logs`: search, ingest, simulate, and verify log integrity.
- `/alerts`: list, retrieve, update, fetch evidence, and run detection.
- `/analytics/dashboard`: dashboard metrics and recent distributions.
- `/servers`: list and administer monitored assets.
- `/rules`: list and update detection rules.
- `/graph`: topology, repeated attackers, blast radius, and attack paths.
- `/ai`: threat analysis, assistant chat, and analysis history.

Bearer JWT authentication is required for protected API calls. Role checks are enforced by the backend; hiding controls in the frontend is not the security boundary.

## Testing and local development

Backend tests:

```powershell
cd backend
python -m pytest -q
```

Or run them without installing Python on Windows after startup:

```powershell
docker compose --env-file .env exec backend python -m pytest -q
```

Backend smoke/diagnostic harness:

```powershell
cd ..
python scripts/verify_system.py
```

Frontend production build:

```powershell
cd frontend
npm ci
npm run build
```

The containerized frontend build can also be checked without installing Node.js:

```powershell
docker compose --env-file .env build frontend
```

For local development outside Docker, configure database URLs and credentials in the environment, run the backend from the project root (`python -m uvicorn backend.app.main:app --reload`), then run `npm run dev` in `frontend`. The Vite dev server proxies `/api` to `http://localhost:8000`.

## Troubleshooting

- **Docker daemon unavailable:** Start Docker Desktop and wait for it to finish starting before rerunning the batch file.
- **Service did not become healthy:** Inspect `docker compose --env-file .env ps` and `docker compose --env-file .env logs --tail=100`.
- **Port already in use:** Change the relevant `*_PORT` value in `.env`, then rerun startup.
- **Login rejected on a new install:** Use `admin` and the `SEED_ADMIN_PASSWORD` value from `.env`. Existing database volumes are not re-seeded over existing users.
- **Ollama advisory fallback:** The core app remains available. Start Ollama on the host, pull the configured model, and confirm `OLLAMA_HOST` in `.env`.
- **Neo4j cannot authenticate after changing its password:** Neo4j stores its initialized password in its data volume. Changing `.env` does not rotate that stored credential; either restore the original password or deliberately reset volumes.

## Known limitations

- The project uses deterministic sample threat indicators and demo telemetry, not a continuously updated threat-intelligence feed.
- The offline AI fallback is rule-grounded advisory text, not an LLM or a substitute for analyst review.
- The in-memory database/graph adapters are for tests and local development only. Production Compose startup requires MongoDB and Neo4j connectivity.
- MongoDB has no database-level authentication in this single-machine academic configuration; its host port is bound to loopback. Do not expose the service or use this setup for production data.
- This academic project does not claim compliance certification, immutable storage, or production-grade multi-tenant isolation.
