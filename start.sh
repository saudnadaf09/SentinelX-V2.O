#!/usr/bin/env bash
# SentinelX one-command start (Linux/macOS). Creates .env with generated secrets on first run.
set -eu
cd "$(dirname "$0")"

command -v docker >/dev/null 2>&1 || { echo "Docker is required (https://docs.docker.com/get-docker/)."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required."; exit 1; }

gen() { if command -v openssl >/dev/null 2>&1; then openssl rand -hex "$1"; else python3 -c "import secrets;print(secrets.token_hex($1))"; fi; }

if [ ! -f .env ]; then
  echo "Creating .env with generated secrets..."
  ADMIN_PW="$(gen 12)"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      SECRET_KEY=*) echo "SECRET_KEY=$(gen 32)";;
      POSTGRES_PASSWORD=*) echo "POSTGRES_PASSWORD=$(gen 16)";;
      BOOTSTRAP_ADMIN_PASSWORD=*) echo "BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PW";;
      *) echo "$line";;
    esac
  done < .env.example > .env
  chmod 600 .env 2>/dev/null || true
  echo "Admin login: admin@sentinelx.local / $ADMIN_PW   (also stored in .env)"
fi

if [ "$(uname -s)" = "Linux" ] && [ -r /proc/sys/vm/max_map_count ] && [ "$(cat /proc/sys/vm/max_map_count)" -lt 262144 ]; then
  echo "WARNING: OpenSearch needs vm.max_map_count >= 262144. Run: sudo sysctl -w vm.max_map_count=262144"
fi

docker compose up -d --build
PORT="$(grep -E '^WEB_PORT=' .env | cut -d= -f2)"; PORT="${PORT:-8080}"
echo
echo "Starting... first start can take 1-3 minutes (OpenSearch is slow to boot)."
echo "  App:      http://localhost:${PORT}"
echo "  API docs: http://localhost:${PORT}/api/docs"
echo "  Demo data: ./scripts/demo.sh   (after the app is up)"
echo "  Logs:      docker compose logs -f backend worker"
