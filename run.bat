@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title SentinelX
echo.
echo  === SentinelX - Easy Mode (no Docker) ===
echo.

set "PY="
where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if not defined PY (
  where python >nul 2>nul
  if not errorlevel 1 set "PY=python"
)
if not defined PY goto nopython
%PY% -c "import sys; sys.exit(0 if sys.version_info[:2]>=(3,10) else 1)"
if errorlevel 1 goto nopython

if not exist "backend\.venv\Scripts\python.exe" (
  echo [1/3] Creating Python environment...
  %PY% -m venv backend\.venv
  if errorlevel 1 goto fail
)
if not exist "backend\.venv\.deps_v2" (
  echo [2/3] Installing backend packages - first time only, needs internet...
  "backend\.venv\Scripts\python.exe" -m pip install --upgrade pip -q
  "backend\.venv\Scripts\python.exe" -m pip install -r backend\requirements-lite.txt
  if errorlevel 1 goto fail
  echo ok> "backend\.venv\.deps_v2"
)

if not exist "frontend\dist\.ui_v2" (
  where npm >nul 2>nul
  if errorlevel 1 goto nonode
  echo [3/3] Building the web interface - first time only, takes a few minutes...
  pushd frontend
  call npm install
  if errorlevel 1 ( popd & goto fail )
  call npm run build
  if errorlevel 1 ( popd & goto fail )
  echo ok> "dist\.ui_v2"
  popd
)

echo.
echo Starting SentinelX...
"backend\.venv\Scripts\python.exe" backend\easy_start.py
goto end

:nopython
echo Python 3.10 or newer is required.
echo Install it from https://www.python.org/downloads/ and TICK "Add python.exe to PATH" in the installer.
echo Then double-click run.bat again.
goto end

:nonode
echo Node.js is required once, to build the web interface.
echo Install the LTS version from https://nodejs.org/ then double-click run.bat again.
goto end

:fail
echo.
echo Something failed. Copy the red/error text above and send it to get help.

:end
echo.
pause
