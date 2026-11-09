@echo off
setlocal
pushd "%~dp0"

where docker >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker CLI was not found.
    popd
    exit /b 1
)

if not exist ".env" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup-env.ps1"
    if errorlevel 1 (
        echo ERROR: Could not prepare Compose configuration.
        popd
        exit /b 1
    )
)

docker compose --env-file .env down --remove-orphans
if errorlevel 1 (
    echo ERROR: Could not stop the project. Check that Docker Desktop is running.
    popd
    exit /b 1
)

echo Services stopped. MongoDB and Neo4j data volumes were preserved.
popd
exit /b 0
