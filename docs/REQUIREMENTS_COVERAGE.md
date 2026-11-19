# Requirements coverage (v2.0: multi-tenant, AI providers, agent, telemetry)

**Legend.** **T** = covered by tests that were *actually executed* in the authoring sandbox (79 unittest cases, all passing).
**W** = implemented and statically checked (syntax, import resolution), with a pytest case written, but **not executed** because the sandbox
had no FastAPI/SQLAlchemy/network. Run `pytest` on your machine to promote W to verified. **P** = partial. **B** = blocked by something only you can supply
(credentials, real machines). **-** = not implemented.

| # | Requirement | Status | Notes |
|---|---|---|---|
| 1 | Preserve project, backup before change, no destructive migration | **W** | Migration `0002` is additive and idempotent; legacy rows go to "Default Workspace". `easy_start.py` copies `backend/data` to `backups/pre-upgrade-*` before any upgrade. Use a Git branch too. |
| 3 | Registration (all fields), unique email/username, Argon2id, login/logout, sessions, rate limits | **W** (validation rules **T**) | Org fields required for Organization accounts. Refresh-token rotation, session list, "sign out everywhere". |
| 3 | Email verification and password reset "with a real provider" | **P / B** | Real single-use tokens (hash stored, expiring). Delivery: SMTP supported; default is *console mode* (no real email; link printed/outbox) and the UI says so. **B:** needs your SMTP credentials. Verified is shown only after the link is used. |
| 3 | Profile management | **W** | Name, password, sessions. Email/username change not implemented. |
| 4 | Individual and organization workspaces, owner = Org Admin, invitations, membership, revoke access | **W** | One organization per user (V1). Individual workspaces cannot invite. Revocation also kills refresh tokens. |
| 4 | Org-level detection rules, integrations, settings | **P** | Org-owned custom rules and per-org on/off of platform rules **(rule scoping T)**; AI settings and retention per org. "Integrations" = endpoints, API keys, syslog sources only. |
| 5 | RBAC: Super Admin, Org Admin, Analyst, Engineer, Viewer | **T** (matrix) / **W** (route enforcement) | Public registration cannot create Super Admin; only the local bootstrap CLI can. Super Admin manages orgs but sees only aggregate counts of tenants. |
| 4/5 | Tenant isolation | **T** (rule engine, event stores) / **W** (all routers) | Org comes from the DB record of the authenticated user, never from the request. Foreign objects return 404. 14 API isolation tests written. |
| 6 | AI providers: OpenAI, Gemini, Anthropic; model + key; test; status; error/rate-limit handling | **T** (clients vs fake server) / **B** (real providers) | Official request shapes, error classification (auth, model, rate_limit, server, network), keys scrubbed from errors, HTTP-200-with-empty-answer is a failure. **Never run against the real vendor APIs: needs your keys.** Keys encrypted at rest (Fernet from `SECRET_KEY`), never returned. |
| 6/14 | AI Investigator on real evidence; evidence/hypothesis/recommendation/unknown split; no fake output | **T** (output validation) / **W** (endpoint) | No provider = HTTP 503 "unavailable" (no canned AI). Cited event ids not in the evidence are dropped. A separate, clearly labelled *rule-based summary (no AI)* exists. |
| 7 | Dashboard from DB, endpoint health, AI status, detection stats | **W** | All counts from the tenant's stored records; ingestion counters only for platform admins (they are global). |
| 7 | Events, alerts, incidents, assets, rules, audit, response modules preserved and tenant-scoped | **W** | Existing pages kept; changes are additive. |
| 8 | Endpoint agent: secure registration, identity, auth, telemetry, health, retry, rotation, revocation, deregistration | **T** (transport/spool/revocation) / **B** (real hosts) | Single-file stdlib agent. Identity = endpoint id returned at first heartbeat. See `docs/AGENT.md`. |
| 9 | Windows collection (Security/System/Application, Sysmon) | **T** (XML parsing, error classes) / **B** | Security + System (selected ids) + Sysmon via `wevtutil`. **Application log is not collected by default (P).** Not run on a real Windows host by the author. |
| 10 | Linux collection (auth, SSH, sudo, journal) | **T** (file collector, filtering, bookmarks) / **B** (journald) | Distro-agnostic: auth.log, secure, else journalctl. |
| 11 | Network: syslog, firewall logs, connection metadata, DNS | **T** (UDP loopback, parsers, port-scan detection) / **P** | A device is "connected" only after a valid datagram from its registered IP. **DNS-specific parsing not implemented. NetFlow/IPFIX not implemented.** |
| 12 | Ingestion pipeline (validate, normalize, preserve raw, dedupe, persist, failures) | **T** (core) / **W** (API) | Idempotent per event id; malformed events quarantined to dead-letter. Per-tenant ingestion-failure *history UI* is **P** (global counters only). |
| 13/14 | Detection, alerts with evidence, incident correlation, notes, assignment, audit | **T** (engine, correlation) / **W** (persistence) | "Configurable automatic incident creation" is **P** (correlation window/rules in `detection-rules/correlation/correlation.yml`; no per-org toggle yet). |
| 15 | LIVE / SIMULATED / TEST / OFFLINE classification | **W** | Class comes from the *endpoint* (server-side), stored on events and alerts. Legacy demo assets/alerts are migrated to SIMULATED; legacy events show UNCLASSIFIED. Polling every 15 s (no websockets). |
| 16 | Response Center honesty | **W** | All actions labelled SIMULATED; catalog says `implemented: false`. **No real response action exists.** |
| 17 | Audit coverage and protection | **W** | Registration, login/failed login/logout, role changes, org changes, endpoint register/revoke/deregister, rule changes, alert/incident updates, AI config/tests, response, export/delete. Append-only trigger on PostgreSQL (0001) and SQLite (0002). |
| 17 | HTTPS, CSRF, XSS, rate limiting, secrets | **P** | HTTPS: terminate TLS at a reverse proxy (Render does). CSRF n/a (bearer header, no cookies). React escapes output; CSP in the Nginx config only. Rate limits are per-process. |
| 17 | Data retention, export, deletion | **T** (store deletion) / **W** | Per-org retention; workspace JSON export + events JSONL; full workspace deletion (audit rows retained). Deleting a single member = deactivate/revoke (**P**). |
| 18 | SQLite locally, PostgreSQL-ready, migrations, indexes, no Redis/Kafka/ES | **W** | Portable column types; PostgreSQL path not run in this version. |
| 19 | Frontend pages | **W** | All requested pages exist; TSX syntax-checked, **never built or rendered by the author**. |
| 20 | Python 3.13.7 / Node 24.19.0 compatibility | **P** | Authored/tested on Python 3.12; backend uses version *ranges* for wheels on 3.13. Frontend deps unchanged (they built on your Node 24). Report any install error. |
| 22 | Regression of existing functionality | **T** (domain) / **W** (API) | The 48 original domain tests still pass; the original API tests were adapted for the new roles. |
