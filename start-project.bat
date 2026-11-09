@echo off
setlocal
pushd "%~dp0"

echo.
echo SentinelGraph-AI startup
echo ----

where docker >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker CLI was not found. Install Docker Desktop and retry.
    goto :failed
)

docker compose version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker Compose v2 is required. Update Docker Desktop and retry.
    goto :failed
)

docker info >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker is installed but its daemon is unavailable.
    echo Start Docker Desktop, wait until it reports Running, then retry.
    goto :failed
)

if not exist ".env.example" (
    echo ERROR: .env.example is missing from the project root.
    goto :failed
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup-env.ps1"
if errorlevel 1 (
    echo ERROR: Could not prepare the local .env configuration.
    goto :failed
)

echo Validating Compose configuration...
docker compose --env-file .env config --quiet
if errorlevel 1 (
    echo ERROR: Compose configuration is invalid. Check .env and docker-compose.yml.
    goto :failed
)

echo Building and starting MongoDB, Neo4j, backend, and frontend...
docker compose --env-file .env up --build --detach --wait --wait-timeout 240
if errorlevel 1 (
    echo ERROR: One or more services failed to become healthy.
    echo Recent service logs:
    docker compose --env-file .env logs --tail=80
    goto :failed
)

echo.
echo SentinelGraph-AI is ready.
echo Frontend:      http://localhost:3000
echo API docs:      http://localhost:8000/docs
echo Backend health: http://localhost:8000/health
echo Neo4j Browser: http://localhost:7474  (username: neo4j; password is in .env)
echo.
docker compose --env-file .env ps
popd
exit /b 0

:failed
popd
exit /b 1
