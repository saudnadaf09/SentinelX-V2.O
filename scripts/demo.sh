#!/usr/bin/env bash
# Seeds demo users and replays the synthetic attack scenario (safe, fictional data).
set -eu
cd "$(dirname "$0")/.."
docker compose exec backend python -m app.cli seed-demo-users
docker compose exec backend python -m app.cli replay-sample
echo "Open the app and look at Alerts, Incidents and the Overview dashboard."
