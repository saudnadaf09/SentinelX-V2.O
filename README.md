# SentinelX - AI-Powered SIEM & XDR-lite

Built by **Saud Nadaf**, 2nd-year B.Tech CSE (Cybersecurity) student at Darbhanga College of Engineering (DCE).
[LinkedIn](https://www.linkedin.com/in/saud-nadaf-41b015343/) · [GitHub](https://github.com/saudnadaf09) · saudnadaf.infosec@proton.me

**License: proprietary, all rights reserved** (see `LICENSE`). Viewing for evaluation is allowed; copying, modifying, redistributing or hosting is not.

A single-developer, lab-scale security monitoring platform: collect endpoint/network telemetry, normalize it,
detect with deterministic YAML rules, correlate related alerts into explainable incidents, map to MITRE ATT&CK,
investigate with an optional AI assistant, and run approval-gated, mock-by-default response actions.

> **Honest scope.** This is a portfolio/lab project, not a commercial SIEM/XDR. Response actions are simulated.
> AI is advisory and optional. Read [Implementation status](#implementation-status) before presenting anything as "working".

## What's new in v2.0
Registration and login (individual or organization), multi-tenant data isolation, 5 roles, invitations, per-workspace AI provider settings
(OpenAI / Gemini / Anthropic, encrypted keys, real connection test), Windows/Linux endpoint agent, syslog ingestion, LIVE / SIMULATED / TEST /
OFFLINE data labelling, workspace export and deletion. **Read `docs/REQUIREMENTS_COVERAGE.md`: it states exactly what was tested and what was not.**

## Features
Authentication + 4-role RBAC (server-side) · collector API keys (hashed, expiring, revocable) · batch ingestion with
validation, idempotency and dead-lettering · ECS-style normalization (Sysmon, Windows Security, Linux auth, Suricata) ·
OpenSearch event search · 12 YAML detection rules (match / threshold / distinct-count / sequence) · explainable
correlation · ATT&CK mapping · alerts + incidents + notes + timeline · AI investigator with rule-based fallback ·
response proposals with dry-run, separation-of-duties approval, expiry, rollback · audit log · incident reports
(MD/HTML/JSON) and CSV exports · React SOC console (16 pages).

## Architecture
```
collector/replay -> POST /api/v1/ingest/events/batch (FastAPI: auth, validation, size/rate limits)
   -> Redis Streams -> worker: normalize -> dedupe -> detect -> alerts+correlation (PostgreSQL) -> index (OpenSearch)
React console (Nginx) <-> FastAPI REST  <->  PostgreSQL (state, audit)  +  OpenSearch (events)
```
Details, data model and every deviation from the blueprint: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start - Easy Mode (no Docker)
Install Python 3.10+ and Node.js LTS, then double-click **`run.bat`** (Linux/macOS: `./run.sh`). It installs
dependencies, builds the UI, creates the database, admin + demo users, loads demo attack data and opens
http://localhost:8000. Logins are written to `DEMO-LOGINS.txt`. See **START-HERE.txt**.
Easy Mode uses one process with SQLite (database + persistent event store) and an in-memory queue; it is meant for
a single machine. The Docker stack below (PostgreSQL, Redis, OpenSearch) is the production-like option.

## Quick start (Docker)
```bash
./start.sh            # Linux/macOS      (Windows: start.bat)
./scripts/demo.sh     # seed demo users + replay the synthetic attack  (Windows: scripts\demo.bat)
```
Open **http://localhost:8080** (API docs: http://localhost:8080/api/docs). Full steps: [SETUP.md](SETUP.md).
Problems: [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Technology stack
Python 3.12 · FastAPI · Pydantic v2 · SQLAlchemy 2 · Alembic · PostgreSQL 16 · Redis 7 Streams · OpenSearch 2.17 ·
React 18 + TypeScript + Vite + Tailwind · Docker Compose · Nginx. Versions are pinned in
`backend/requirements.txt`, `frontend/package.json` and `docker-compose.yml`.

## Screenshots
Placeholders - capture after your first run: `docs/screenshots/overview.png`, `alerts.png`, `incident-timeline.png`.

## Sample event replay
`docker compose exec backend python -m app.cli replay-sample` ingests 47 synthetic events (RFC 5737 IPs, fictional
hosts) that trigger all 12 rules: SSH/Windows brute force, success-after-failures, encoded PowerShell (plus an
excluded benign automation run), script interpreter, temp-path execution, service-stop, scheduled task, new
privileged account, outbound C2-style connection and a port scan. A static copy is in `sample-data/sample_events.jsonl`.

## Testing
```bash
cd backend && pip install -r requirements-dev.txt && pytest          # API + domain tests, no Docker needed
python -m unittest discover -s tests -p "test_domain_*.py"           # domain tests only, stdlib only
cd ../frontend && npm install && npm run typecheck && npm run build
```

## Security notes
Argon2id passwords · short-lived JWT access tokens + rotating refresh tokens · deny-by-default RBAC on every route ·
HMAC-hashed collector keys shown once · request-size and rate limits · strict input schemas, field allowlists for
search · no shell execution anywhere · AI sees redacted, bounded evidence and cannot act · append-only audit (DB
trigger on PostgreSQL) · secrets only via environment. Known weaknesses are listed below - read them.

## Implementation status
Legend: **T** = covered by tests that were actually executed in the build environment; **W** = written and
statically checked only (syntax/import resolution) but **not executed** because the build sandbox had no network,
Docker, or Python web/ORM packages. Run the test suite on your machine to promote W items to verified.

| Module | Status |
|---|---|
| Event normalization (Sysmon, Win Security, Linux auth, Suricata) | **T** (47 domain tests) |
| Detection engine, 12 rules, thresholds, sequence, exclusions, idempotency | **T** |
| Correlation logic and reasons | **T** |
| MITRE mapping table (rules reference only known techniques) | **T** |
| Query validation, in-memory store/queue (dedupe, retry, dead-letter), SQLite event store | **T** |
| Redaction, AI output validation, deterministic AI fallback | **T** |
| Response action allowlist + mock adapter | **T** |
| FastAPI app, auth/JWT/Argon2, RBAC, all REST routes | **W** (pytest suite written, not run) |
| SQLAlchemy models, Alembic baseline migration, PostgreSQL audit trigger | **W** |
| Redis Streams queue, OpenSearch store/mappings/retention | **W** |
| Worker pipeline, alert upsert, auto-incident correlation | **W** |
| Response approval workflow (service + API) | **W** |
| LLM providers (Anthropic / OpenAI-compatible) | **W** (never called) |
| Reports and CSV export | **W** |
| React console (16 pages) | **W** (TSX syntax-checked; `vite build` not run) |
| Docker Compose, Nginx, start scripts | **W** |
| Easy Mode launcher (`run.bat`/`run.sh`, `easy_start.py`, UI served by the API) | **W** (never run end-to-end) |
| Playwright UI tests | Planned - not included |
| Real Sysmon/auditd/Fluent Bit collectors | Planned - see docs/INGESTION.md |
| Real (non-mock) response adapters | Not implemented, by design |
| Performance numbers (50 events/s, <5 s latency) | **Not measured** - targets only |

## Known limitations
- Rule engine window state is in memory; a worker restart forgets partially built thresholds.
- Single worker assumed; engine state is not shared across workers.
- Rate limiting is per-process. Tokens live in `sessionStorage` (XSS would expose them); CSP is set in Nginx.
- `package-lock.json` is not shipped (no network at build time); `npm install` creates it. Commit it afterwards.
- Baseline migration uses `create_all`; generate explicit migrations for future schema changes.
- OpenSearch runs with its security plugin disabled for the lab and is never published to the host.
- ATT&CK data is a curated subset; verify names/tactics against the current release.
- Alert list filtering by technique is done in Python (fine at lab scale, not for millions of alerts).

## Roadmap
Playwright E2E, real collectors (Fluent Bit configs), Sigma import subset, rule test UI, stateful rule recovery from
OpenSearch, MFA/SSO, explainable risk scoring, lab firewall response adapter, load-test harness with published numbers.
