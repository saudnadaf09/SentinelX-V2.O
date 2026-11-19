# v2.0 completion report

## Existing architecture (inspected before changes)
FastAPI + SQLAlchemy 2 (SQLite locally / PostgreSQL via Docker), Alembic baseline `0001`, in-process pipeline (memory queue + SQLite event store in Easy Mode),
rule engine (framework-free), React/Vite/Tailwind SPA served by the API. Single tenant, 4 global roles, no registration, mock-only response.

## Database changes (migration `0002_multitenancy`, additive and idempotent)
New tables: `organizations`, `auth_tokens`, `org_rule_overrides`, `ai_settings`.
New columns: `users` (username, org_id, email_verified) · `refresh_tokens` (ip, user_agent) · `assets` (org_id, data_class, agent_version, os_version, ip_address, source_ip,
collection_status, last_heartbeat_at, enrolled_at, deregistered_at) · `alerts` (org_id, data_class) · `incidents`/`response_actions`/`audit_logs`/`detection_rules` (org_id) · `organizations.retention_days`.
Indexes: per-table `org_id`, unique `users.username`, unique `(assets.org_id, assets.hostname)` replacing the global hostname uniqueness.
Data: "Default Workspace" organization created; every legacy row assigned to it; legacy `admin` users become `super_admin`; demo-tagged assets/alerts classified SIMULATED;
legacy audit rows keep `org_id NULL` (treated as the default workspace); SQLite append-only triggers on `audit_logs`. No table is dropped or rewritten.

## Files
**Created:** `backend/app/domain/{tenancy,secrets_util,accounts,mailer,ai_providers}.py`, `backend/app/ingest/syslog_listener.py`, `backend/app/services/{account,org}_service.py`,
`backend/app/api/v1/{org,platform,agent}.py`, `backend/alembic/versions/0002_multitenancy.py`, `agent/*`, `frontend/src/pages/{Register,AccountLinks,Profile,Team,Organization,AISettings,Platform}.tsx`,
`backend/tests/test_domain_{tenancy,accounts,ai_providers,agent_syslog}.py`, `backend/tests/test_api_tenancy.py`, `docs/{AGENT,REQUIREMENTS_COVERAGE,ENHANCEMENT_REPORT}.md`.
**Modified:** models, config, permissions, deps, serializers, schemas, container, main, cli, easy_start, run scripts, requirements, rule engine, normalizer, query model, all three event stores,
pipeline, ingest/alert/incident/response/audit/rule/ai/report services, every API router, Login, Layout, Overview, Assets, AI Investigator, Threat Detection, Response Center, Settings, Alerts, AlertDetail, UI kit.
**Preserved:** all existing pages and APIs (paths unchanged), rules, correlation, response workflow, local Windows workflow.

## Environment variables (backend/.env)
`MAIL_MODE` (console|smtp) · `SMTP_HOST/PORT/USER/PASSWORD/STARTTLS` · `MAIL_FROM` · `FRONTEND_BASE_URL` · `REQUIRE_EMAIL_VERIFICATION` · `ALLOW_REGISTRATION` ·
`SYSLOG_UDP_PORT` · `SYSLOG_BIND` · `OUTBOX_DIR` · optional platform-wide AI default `AI_PROVIDER/AI_API_KEY/AI_MODEL/AI_BASE_URL` · existing `SECRET_KEY` etc.
**`SECRET_KEY` now also encrypts stored AI keys: changing it makes them unreadable (re-enter them).**

## Test results (honest)
**Executed and passing: 79 / 79** (`python -m unittest discover -s tests -p "test_domain_*.py"`):
normalizer (9), rule engine/negative fixtures/idempotency (21), tenant isolation of rule state and alert keys (5), memory + SQLite store isolation incl. legacy docs (5),
registration validation, encryption, tokens, console/SMTP mail failure honesty, role matrix (9), AI provider clients vs local fake server: request shapes, 401/404/429/500 classification,
key scrubbing, empty-200 = failure, unreachable host (4), syslog parsing/decision logic/UDP loopback/port-scan detection, agent XML+Linux collectors+spool+outage+revoked key (13), plus the pre-existing suites.
**Written, NOT executed (need `pip install -r backend/requirements-dev.txt`, then `pytest`):** `test_api_flow.py` (10) and `test_api_tenancy.py` (14: registration, duplicates, restart persistence,
logout/rotation, verification and reset single-use, cross-tenant denial on 14 routes, same IP/hostname in two orgs, per-org rule override, invitations and roles, platform admin limits,
AI key never returned/never "connected" after a failed test, deregistration, export without secrets, workspace deletion, tenant audit).
**Not tested at all:** real OpenAI/Gemini/Anthropic calls, real SMTP delivery, real Windows/Linux collection, PostgreSQL, the frontend build/render, Python 3.13/Node 24 installs.

## Known limitations
One organization per user; rules are YAML (no visual rule builder); response actions are simulated only; per-process rate limits and in-memory queue in Easy Mode;
no DNS/NetFlow parsing; Application event log not collected by default; automatic incident creation not configurable per org; platform ingestion counters are global;
SQLite is single-writer (use PostgreSQL for many tenants); tokens live in `sessionStorage`.

## Security considerations
Argon2id; keyed-hash single-use tokens; no account enumeration on reset; login throttled per IP and per identifier; encrypted AI keys; keys scrubbed from errors and audit; SSRF avoided by
fixed provider hosts (custom base URL only via server env); public registration cannot produce privileged roles; tenant filter is the first predicate of every query; audit is append-only.
Production: HTTPS reverse proxy, PostgreSQL, SMTP, strong `SECRET_KEY`, back up `backend/data`, disable registration (`ALLOW_REGISTRATION=false`) if not wanted.

## PostgreSQL / production path
Set `DATABASE_URL=postgresql+psycopg://...`, run `alembic upgrade head`, use the Docker stack (`docker-compose.yml`) or run Redis/OpenSearch separately; move rate limiting to a shared store;
put the API behind TLS; schedule backups; consider one worker per partition for the rule engine (state is in memory).
