# SentinelGraph-AI audit report

## Findings and severity

| Severity | Finding | Resolution |
|---|---|---|
| High | The backend image copied `app/` into `/app` but launched `backend.app.main`, so the image import path did not match its filesystem. | Docker build layout now preserves `backend.app`; the image runs as a non-root user and has a health check. |
| High | JWT, Neo4j, and seeded account passwords were fixed values in tracked files; the login page also prefilled a known admin password. | First-run Windows startup generates random local values into ignored `.env`; production config rejects weak JWT/Neo4j secrets; login fields are blank. Test credentials are confined to test setup. |
| High | Database connection failures silently fell back to in-memory stores, allowing a deployment to appear usable while losing data on restart. | In-memory adapters remain for tests/development and are reported as degraded; production startup now fails if MongoDB or Neo4j is unavailable. |
| High | The frontend used `http://localhost:8000` as its API base, which is the browser host and bypasses the Nginx service network in Docker. | The frontend uses relative `/api/v1`; Nginx proxies it to the backend and Vite proxies it during local development. |
| Medium | Rule enable/disable and saved threshold/window values were not used by the detector. | The detection pipeline loads stored rule configuration and applies enabled state, thresholds, and windows. |
| Medium | In-memory graph responses and attack-path fallback returned prewritten attacker/path data unrelated to current telemetry. | Graph views now derive from graph nodes/edges and return empty results when no matching evidence exists. |
| Medium | Log integrity verification did not cover message, server name, or destination IP, and the API reported the stored hash as both stored and calculated. | New version-2 record hashes cover those normalized fields; old version-1 hashes remain verifiable, and the API returns the recomputed value. |
| Medium | Search patterns were passed to MongoDB as regular expressions, and the in-memory adapter did not implement regex filtering. | User search is escaped for literal matching; the development/test adapter now supports the same regex filters. |
| Low | Dashboard alert totals were capped by a 2,000-record read; in-memory update/delete behavior also differed from MongoDB. | Alert totals now use an exact count and severity/status counts stream through the collection; the adapter supports `$inc` and correct delete counts. |

## Verification performed

- Backend test suite: **29 passed**.
- `scripts/verify_system.py`: passed in explicit in-memory test mode; it verified password/JWT handling, log hashes, all six detection families, seeded alerts, graph-derived data, AI fallback, and alert updates.
- Python `compileall`: passed.
- Frontend TypeScript/Vite production build: passed. Vite reports a large JavaScript bundle warning.
- Frontend lint: completed without errors; existing unused-import and React hook warnings remain.
- `docker compose --env-file .env.example config --quiet`: passed.

## Not verified in this environment

The Docker CLI is installed, but no Docker daemon is available. Therefore image builds, Compose service startup, and live MongoDB/Neo4j health checks could not be executed here. The app tests and diagnostics use non-persistent in-memory adapters, not live databases. Ollama was not running; only the deterministic fallback behavior was exercised.

MongoDB in this academic single-machine Compose setup has no database-level authentication and is bound to loopback. Do not expose it or use this configuration for production data.
