@echo off
setlocal
pushd "%~dp0"

echo WARNING: This permanently deletes all SentinelGraph-AI MongoDB and Neo4j data.
echo This action cannot be undone. The local .env file is not deleted.
echo.
set /p "CONFIRM=Type DELETE to continue: "
if /I not "%CONFIRM%"=="DELETE" (
    echo Reset cancelled. No database volumes were removed.
    popd
    exit /b 0
)

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

docker compose --env-file .env down --volumes --remove-orphans
if errorlevel 1 (
    echo ERROR: Reset failed. Check that Docker Desktop is running.
    popd
    exit /b 1
)

echo Database volumes removed. Run start-project.bat to initialize a clean install.
popd
exit /b 0
