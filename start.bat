@echo off
REM SentinelX one-command start (Windows). Requires Docker Desktop.
setlocal
cd /d "%~dp0"

where docker >nul 2>nul
if errorlevel 1 (
  echo Docker Desktop is required: https://docs.docker.com/desktop/install/windows-install/
  exit /b 1
)

if not exist .env (
  echo Creating .env with generated secrets...
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\init-env.ps1"
  if errorlevel 1 exit /b 1
)

docker compose up -d --build
if errorlevel 1 exit /b 1
echo.
echo Starting... first start can take 1-3 minutes (OpenSearch is slow to boot).
echo   App:      http://localhost:8080   (or the WEB_PORT in .env)
echo   API docs: http://localhost:8080/api/docs
echo   Demo data: scripts\demo.bat   (after the app is up)
echo   Logs:      docker compose logs -f backend worker
endlocal
