# Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `SECRET_KEY must be set ...` / compose error "Set SECRET_KEY" | `.env` missing or incomplete. Run `start.sh`/`start.bat`, or fill it from `.env.example`. |
| OpenSearch container restarts / exits (Linux) | `sudo sysctl -w vm.max_map_count=262144` (persist in `/etc/sysctl.conf`). |
| OpenSearch unhealthy, out-of-memory | Give Docker >= 4 GB RAM (Docker Desktop > Settings > Resources). Heap is 512 MB in `docker-compose.yml`. |
| Backend waits/restarts at start | It waits for Postgres/Redis/OpenSearch health. First start can take 3 minutes. `docker compose logs backend`. |
| Cannot log in | Admin is only created when **no users exist**. Check `docker compose logs backend \| grep bootstrap`. To start over: `docker compose down -v` then start again. |
| Login says "too many attempts" | Login is limited to 10/min per IP. Wait a minute. |
| Dashboard empty | No events yet. Run `scripts/demo.sh`. Check `docker compose logs worker` for errors and the Overview pipeline counters (queue depth, dead-letter backlog). |
| Events visible but alerts missing | Rules reload every 30 s; check *Threat Detection* shows rules enabled; look at worker logs for "rule evaluation failed". |
| Events in dead-letter backlog | Quarantined (malformed) or failed 3 times. Inspect with `docker compose exec backend python -c "from app.core.container import get_queue; print(get_queue().dead_letters(5))"`; after fixing the cause: `python -m app.cli requeue-dead-letters`. |
| Searching right after ingest shows nothing | OpenSearch refreshes about once per second. |
| `port is already allocated` | Change `WEB_PORT` in `.env` (and `CORS_ORIGINS`). |
| Windows: `start.bat` cannot run PowerShell | Run it from a normal terminal, or create `.env` manually (see SETUP.md). |
| Frontend build fails in Docker | `docker compose build web --no-cache`; run `cd frontend && npm install && npm run build` locally to see the error. Note: the frontend was not built during authoring - please report/fix any error output. |
| 401 right after being idle | Access tokens last 30 min; refresh happens automatically. If the refresh token expired (7 days) sign in again. |
| Collector gets 401 | Key revoked/expired, wrong header (`X-API-Key`), or `SECRET_KEY` changed since the key was issued. |
| Collector gets 413 / 400 | Batch over 1 MB / 500 events, or event schema invalid - the response lists reasons per event index. |
