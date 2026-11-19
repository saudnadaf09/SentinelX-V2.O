# Setup

## Requirements
- **Docker Desktop / Docker Engine with Compose v2** (needed for PostgreSQL, Redis and OpenSearch - these cannot be
  replaced by anything lighter in the full stack).
- ~4 GB free RAM (OpenSearch is capped at 512 MB heap), ~3 GB disk.
- Linux only: `sudo sysctl -w vm.max_map_count=262144` (OpenSearch requirement).

## 1. Start
1. Extract the ZIP, open the folder in VS Code (`code .`).
2. Run `./start.sh` (Windows: double-click or run `start.bat`).
   - On first run it copies `.env.example` to `.env`, **generates `SECRET_KEY`, `POSTGRES_PASSWORD` and a random
     admin password**, and prints the admin login. They are stored in `.env` (gitignored).
   - Manual alternative: `cp .env.example .env`, set `SECRET_KEY` (32+ random chars), `POSTGRES_PASSWORD`, optionally
     `BOOTSTRAP_ADMIN_PASSWORD`, then `docker compose up -d --build`.
3. Wait 1-3 minutes on first start. Check: `docker compose ps` (all `healthy`) or `docker compose logs -f backend worker`.

| What | URL |
|---|---|
| Application | http://localhost:8080 |
| API docs (Swagger) | http://localhost:8080/api/docs (disabled when `APP_ENV=production`) |
| Direct API (localhost only) | http://127.0.0.1:8000/api/v1/health |

## 2. Administrator account
Created once, on first start, when no users exist: `BOOTSTRAP_ADMIN_EMAIL` (default `admin@sentinelx.local`) with
`BOOTSTRAP_ADMIN_PASSWORD`. If that is empty a random password is generated and printed once in the backend log:
`docker compose logs backend | grep "generated password"`. There is **no default password** in the code or repo.
Change it under *Settings*.

## 3. Demo without a real endpoint
```bash
./scripts/demo.sh          # Windows: scripts\demo.bat
```
This creates `analyst@`, `engineer@` and `viewer@sentinelx.local` demo users with **random passwords printed once**,
registers `LAB-WIN-01` / `LAB-LNX-01` and replays the synthetic scenario. Within seconds you should see alerts,
two auto-correlated incidents, events and dashboard charts. Demo users are refused when `APP_ENV=production`.

Suggested walkthrough: Overview -> Alerts (open *Successful login after a burst of failures*) -> Create/open the
incident -> timeline + notes -> AI Investigator -> Response Center (propose as analyst, approve as engineer) ->
Audit Logs -> Reports.

## 4. Configuration (`.env`)
| Variable | Purpose |
|---|---|
| `SECRET_KEY` | JWT signing + API-key hashing pepper. Rotating it invalidates sessions and collector keys. |
| `POSTGRES_*` | Database credentials (internal network only). |
| `BOOTSTRAP_ADMIN_*` | First admin (see above). |
| `EVENT_RETENTION_DAYS` | Daily OpenSearch indices older than this are deleted hourly by the worker. |
| `AI_PROVIDER` / `AI_API_KEY` / `AI_MODEL` / `AI_BASE_URL` | Optional AI. `anthropic` or `openai_compatible` (e.g. local Ollama). Leave `disabled` for rule-based analysis. Evidence is redacted before sending, but only enable external providers for synthetic/lab data. |
| `CORS_ORIGINS` | Allowed browser origins. |

Restart after editing: `docker compose up -d`.

## 5. Developing without rebuilding containers
Backend + frontend on the host, infrastructure in Docker (or lite mode below):
```bash
# infrastructure only
docker compose up -d postgres redis opensearch
# backend (Python 3.12)
cd backend && python -m venv .venv && . .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
# create backend/.env with SECRET_KEY, DATABASE_URL=postgresql+psycopg://sentinelx:<pw>@localhost:5432/sentinelx (publish ports first)
alembic upgrade head && python -m app.cli bootstrap
uvicorn app.main:app --reload           # http://localhost:8000/api/docs
python -m app.workers.run               # second terminal
# frontend
cd frontend && npm install && npm run dev    # http://localhost:5173 (proxies /api to :8000)
```
The default compose file does not publish Postgres/Redis/OpenSearch to the host; add `ports:` entries on `127.0.0.1` for this workflow.

### Docker-free "lite" mode (backend only)
SQLite + in-memory queue/store, pipeline runs inline. **Data is lost on restart; not for real use.** Copy
`.env.lite.example` to `backend/.env`, then `alembic upgrade head`, `python -m app.cli bootstrap`,
`python -m app.cli replay-sample`, `uvicorn app.main:app`. Run `pytest` the same way (no Docker needed).

## 6. Sending real telemetry
See [docs/INGESTION.md](docs/INGESTION.md). Only connect systems you own or are explicitly authorized to monitor.

## 7. Stop / reset
`docker compose down` (keep data) · `docker compose down -v` (delete all data volumes).
