#!/usr/bin/env bash
# SentinelX Easy Mode (no Docker) for Linux/macOS.
set -e
cd "$(dirname "$0")"
echo; echo " === SentinelX - Easy Mode (no Docker) ==="; echo

PY=""
for c in python3 python; do command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys;sys.exit(0 if sys.version_info[:2]>=(3,10) else 1)' && PY="$c" && break || true; done
[ -n "$PY" ] || { echo "Python 3.10+ is required (https://www.python.org/downloads/)."; exit 1; }

if [ ! -x backend/.venv/bin/python ]; then echo "[1/3] Creating Python environment..."; "$PY" -m venv backend/.venv; fi
if [ ! -f backend/.venv/.deps_v2 ]; then
  echo "[2/3] Installing backend packages (first time only, needs internet)..."
  backend/.venv/bin/python -m pip install --upgrade pip -q
  backend/.venv/bin/python -m pip install -r backend/requirements-lite.txt
  echo ok > backend/.venv/.deps_v2
fi
if [ ! -f frontend/dist/.ui_v2 ]; then
  command -v npm >/dev/null 2>&1 || { echo "Node.js is required once to build the web UI (https://nodejs.org/, LTS)."; exit 1; }
  echo "[3/3] Building the web interface (first time only)..."
  (cd frontend && npm install && npm run build && echo ok > dist/.ui_v2)
fi
echo; echo "Starting SentinelX..."
exec backend/.venv/bin/python backend/easy_start.py
