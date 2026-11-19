# SentinelX — AI-Assisted SIEM & XDR-Lite Platform

<p align="center">
  <strong>Security Monitoring · Threat Detection · Digital Investigation · Incident Response</strong>
</p>

<p align="center">
  <a href="https://sentinelx-v2-85pr.onrender.com">Live Application</a> ·
  <a href="https://github.com/saudnadaf09/SentinelX-V2.O">GitHub Repository</a> ·
  <a href="https://www.linkedin.com/in/saud-nadaf-41b015343/">LinkedIn</a>
</p>

---

## Overview

**SentinelX** is a lab-scale, AI-assisted Security Information and Event Management (SIEM) and XDR-lite platform designed to demonstrate security telemetry collection, event normalization, rule-based threat detection, alert correlation, incident investigation, and controlled response workflows.

The platform brings endpoint and network security telemetry into a centralized monitoring environment. It processes incoming events, evaluates detection rules, generates alerts, correlates related activity into incidents, and provides analysts with investigation and reporting capabilities.

SentinelX combines deterministic detection logic with optional AI-assisted investigation. AI is intended to support analysts with contextual analysis; it does not replace the underlying detection engine.

The project is developed as a cybersecurity engineering and research-oriented portfolio project, with an emphasis on practical security operations, defensive monitoring, explainable detection, and secure application design.

**Project classification:** Educational / Research / Lab-scale cybersecurity platform.

> SentinelX is not a commercial SIEM or enterprise XDR replacement. Response Center actions are simulated through a mock adapter. Do not rely on this project as the sole security control for production infrastructure.

---

## Project Information

| Attribute | Details |
|---|---|
| Project | SentinelX |
| Version | 2.0 project release |
| Backend package version | 1.0.0 |
| Category | SIEM / XDR-lite / Security Operations |
| Project type | Cybersecurity engineering project |
| Backend | Python, FastAPI |
| Frontend | React, TypeScript, Vite |
| Database | SQLite in Easy/hosted mode; PostgreSQL in Docker stack |
| Queue | In-memory in Easy/hosted mode; Redis Streams in Docker stack |
| Event search | SQLite-backed hosted mode; OpenSearch in Docker stack |
| Detection | YAML-based deterministic rule engine |
| AI | Optional AI-assisted investigation |
| Response | Mock / simulated |
| License | MIT |
| Author | Saud Nadaf |

**Live application:** https://sentinelx-v2-85pr.onrender.com

**Repository:** https://github.com/saudnadaf09/SentinelX-V2.O

---

## Core Objectives

SentinelX aims to provide a practical implementation of the following security operations concepts:

- Centralized security event collection and monitoring.
- Normalization of heterogeneous endpoint and network telemetry.
- Deterministic, explainable detection using YAML rules.
- Alert generation, deduplication, and incident correlation.
- MITRE ATT&CK technique references.
- Endpoint registration, authentication, and health monitoring.
- Role-based access control and workspace isolation.
- AI-assisted investigation with evidence-aware output.
- Auditable, approval-gated simulated response workflows.
- Incident reporting and security activity auditing.

---

## Key Features

### 1. Identity, Authentication & Access Management

- User registration and authentication.
- Individual and organization workspaces.
- Email verification and password-reset workflows.
- Password hashing using Argon2id.
- Access-token and refresh-token session management.
- Refresh-token rotation and session revocation.
- Role-based access control (RBAC).
- Organization invitations and membership management.
- Organization-level data isolation.

### 2. Role-Based Access Control

The application implements a role and permission model.

| Role | General responsibility |
|---|---|
| Super Admin | Platform-level administration |
| Org Admin | Organization and member management |
| Analyst | Monitoring, investigation, and incident analysis |
| Engineer | Technical security operations and permitted response workflows |
| Viewer | Read-only access to permitted information |

Authorization is enforced by backend permission checks. Hiding a UI control is not treated as a security boundary.

### 3. Endpoint Monitoring

SentinelX includes a lightweight Python endpoint agent for Windows and Linux.

**Windows telemetry sources:**
- Windows Security Event Log.
- Windows System Event Log.
- Selected Sysmon events, when Sysmon is installed.

**Linux telemetry sources:**
- Authentication logs.
- SSH authentication activity.
- Sudo activity.
- Selected user and group management events.
- Journal-based collection where supported.

Agent capabilities include:

- Endpoint registration and identity.
- Authenticated communication with the server.
- Heartbeat and endpoint health reporting.
- Local event spooling.
- Retry and backoff handling.
- Idempotent event delivery.
- Credential rotation and revocation.
- Endpoint deregistration.

The agent is designed for security-log collection. It does not intentionally collect personal documents, browser data, passwords, or unrelated user files.

See [`docs/AGENT.md`](docs/AGENT.md) for installation and operational instructions.

**Validation note:** Agent parsers, spool/retry behavior, and related logic have automated test coverage. Real Windows Event Log and Linux journald collection must still be validated on the target machines.

### 4. Network & Syslog Monitoring

The platform supports syslog-based ingestion and selected firewall/network event formats.

Capabilities include:

- UDP syslog ingestion.
- RFC 3164 and RFC 5424 message parsing.
- Selected key-value firewall log parsing.
- SSH and sudo message parsing.
- Registered network-device association.
- Source-IP validation for registered devices.
- Network event normalization.

DNS-specific parsing and NetFlow/IPFIX processing are not currently implemented.

See [`docs/INGESTION.md`](docs/INGESTION.md).

### 5. Event Ingestion & Normalization

The ingestion pipeline accepts event batches through authenticated API endpoints.

Processing includes:

1. Collector authentication.
2. Event validation.
3. Host identity association.
4. Source-specific normalization.
5. Duplicate detection.
6. Event processing and rule evaluation.
7. Alert generation and correlation.
8. Event storage and search.

Supported event families include:

- Sysmon.
- Windows Security.
- Linux authentication.
- Suricata EVE JSON.
- Selected syslog and firewall messages.

The pipeline supports event identifiers, batch idempotency, rejected-event reporting, and dead-letter handling in the applicable queue configuration.

### 6. Detection Engine

SentinelX uses deterministic YAML-based detection rules.

Detection types include:

- `match`
- `threshold`
- `distinct_count`
- `sequence`

The rule engine supports condition operators such as:

- Equality and inequality.
- Membership and exclusion.
- String matching.
- Regular expressions.
- Field existence checks.
- Numeric comparisons.
- Logical combinations.

Rules can include exclusion conditions for known-benign activity.

Detection does not depend on AI. This keeps rule evaluation deterministic and explainable.

**Detection rule categories:**

| Category | Example detections |
|---|---|
| Authentication | SSH brute force, Windows brute force |
| Account activity | New account creation |
| Privilege changes | Privileged group membership changes |
| Network | Port scanning, suspicious outbound activity |
| Persistence | Scheduled task and service activity |
| Process activity | Suspicious PowerShell, script interpreters |
| Defense evasion | Suspicious log-clearing activity |
| Correlation | Related alert activity across a time window |

Rules are maintained under [`detection-rules/`](detection-rules/).

API-created custom rules start disabled until explicitly enabled.

### 7. Alert & Incident Management

The platform provides:

- Detection alert generation.
- Alert deduplication.
- Rule and evidence references.
- Incident correlation.
- Incident timelines.
- Analyst notes and investigation context.
- Incident status and assignment workflows.
- Audit history.

Related alerts can be correlated using shared host/user context or qualifying source-IP information within the configured correlation window.

### 8. MITRE ATT&CK References

Detection and investigation workflows include MITRE ATT&CK technique references where applicable.

This helps analysts connect observed activity with recognized adversary tactics and techniques.

MITRE ATT&CK is a reference framework; SentinelX does not claim complete ATT&CK coverage.

### 9. AI-Assisted Investigation

AI investigation is optional and configured separately from deterministic detection.

The AI workflow is designed to help analysts:

- Interpret available alert evidence.
- Review suspicious activity.
- Organize findings and hypotheses.
- Produce recommendations.
- Identify uncertainty and missing evidence.

Security controls include encrypted storage for configured AI credentials and validation of structured investigation output.

The platform also distinguishes rule-based summaries from actual AI-generated investigation results. A rule-based summary must not be interpreted as an AI analysis.

**Important:** AI output is advisory. Analysts must independently verify findings before taking action. External AI providers should only receive data that is appropriate and authorized for disclosure.

### 10. Response Center

SentinelX includes a controlled response workflow for demonstrating security operations concepts.

The workflow includes:

- Response proposals.
- Parameter validation.
- Dry-run behavior.
- Approval permissions.
- Separation of requester and approver.
- Approval expiration.
- Auditing.
- Rollback workflow.

**Current implementation:** The response adapter is mock-based. No real endpoint isolation, firewall modification, process termination, or other production response action is executed.

### 11. Audit & Reporting

The application includes security activity auditing and reporting capabilities.

Audited activities include relevant authentication, organization, endpoint, rule, investigation, response, and administrative operations.

The platform supports workspace-related export and reporting workflows. Audit records are protected against ordinary modification through append-only database mechanisms in the supported database implementations.

---

## Architecture

SentinelX supports two distinct runtime configurations. The hosted single-container deployment and the advanced Docker lab stack must not be confused with each other.

### A. Easy Mode / Hosted Deployment

The lightweight configuration uses:

- FastAPI backend.
- React frontend served by the backend deployment.
- SQLite database.
- In-memory queue.
- SQLite-backed event storage.
- YAML detection rules.
- Optional AI integration.

The root `Dockerfile` builds the frontend and packages it with the Python backend.

```text
                    User / Analyst
                          |
                          v
                 React Web Interface
                          |
                          v
                   FastAPI Backend
                          |
             +------------+------------+
             |            |            |
             v            v            v
          SQLite      In-Memory     YAML Rules
          Database      Queue       Detection
             |            |            |
             +------------+------------+
                          |
                          v
                   Alerts & Incidents
                          |
                          v
                 Investigation / Reports
```

This configuration is suitable for lightweight hosting, demonstrations, and individual lab usage.

### B. Advanced Docker Lab Stack

The Docker Compose configuration provides a more infrastructure-oriented lab architecture.

| Component | Responsibility |
|---|---|
| Nginx web service | Frontend serving and reverse proxy |
| FastAPI backend | API, authentication, business logic |
| Worker | Event processing and detection pipeline |
| PostgreSQL | Relational application data |
| Redis Streams | Event queue and processing buffer |
| OpenSearch | Event indexing and search |

```text
 Endpoint Agent / Syslog
          |
          v
    Nginx / Web
          |
          v
    FastAPI Backend
          |
          v
     Redis Streams
          |
          v
        Worker
          |
          +------> Normalize
          |
          +------> Deduplicate
          |
          +------> Detect
          |
          +------> Correlate
          |
          +------> Index Events
          |
          v
 PostgreSQL + OpenSearch
          |
          v
 React Security Console
```

The Docker Compose configuration uses PostgreSQL 16, Redis 7, and OpenSearch 2.17.

The OpenSearch security plugin is disabled in this local lab configuration. Do not expose these internal services directly to untrusted networks.

---

## Technology Stack

### Backend

- Python 3.12 (primary authored runtime).
- FastAPI.
- Uvicorn.
- Pydantic v2.
- SQLAlchemy 2.
- Alembic.
- PyJWT.
- Argon2.
- PyYAML.
- Cryptography.
- Redis client.
- OpenSearch client.
- PostgreSQL driver.

### Frontend

- React 18.
- TypeScript.
- Vite 5.
- React Router.
- Recharts.
- Tailwind CSS 3.
- PostCSS.

### Infrastructure

- Docker.
- Docker Compose.
- PostgreSQL 16.
- Redis 7.
- OpenSearch 2.17.
- Nginx.
- Render deployment support.

### Endpoint Agent

- Python standard library.
- Windows Event Log access through `wevtutil`.
- Linux authentication-log and journal collection.
- HTTPS-based communication.
- Local spool and retry mechanisms.

---

## Repository Structure

```text
SentinelX/
│
├── agent/
│   ├── sentinelx_agent.py
│   ├── install-windows.ps1
│   └── ...
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── domain/
│   │   ├── infra/
│   │   ├── ingest/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── workers/
│   │   └── main.py
│   ├── alembic/
│   ├── tests/
│   ├── requirements.txt
│   └── requirements-lite.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── ...
│   ├── package.json
│   └── vite.config.ts
│
├── detection-rules/
│   ├── authentication/
│   ├── correlation/
│   ├── network/
│   ├── persistence/
│   └── process/
│
├── docs/
│   ├── AGENT.md
│   ├── ARCHITECTURE.md
│   ├── ENHANCEMENT_REPORT.md
│   ├── INGESTION.md
│   └── REQUIREMENTS_COVERAGE.md
│
├── sample-data/
│   ├── README.md
│   └── sample_events.jsonl
│
├── scripts/
│   ├── demo.bat
│   ├── demo.sh
│   └── init-env.ps1
│
├── Dockerfile
├── docker-compose.yml
├── run.bat
├── run.sh
├── start.bat
├── start.sh
├── SETUP.md
├── START-HERE.txt
├── TROUBLESHOOTING.md
├── LICENSE
└── README.md
```

---

## Installation & Quick Start

### Option 1 — Easy Mode (Recommended for Local Evaluation)

Easy Mode does not require Docker.

**Requirements:**

- Windows, Linux, or macOS.
- Python 3.10 or newer.
- Node.js and npm for the initial frontend build.
- Internet access for the initial dependency installation.

**Windows:**

1. Clone or download the repository.
2. Open the project directory.
3. Run:

```bat
run.bat
```

**Linux / macOS:**

```bash
chmod +x run.sh
./run.sh
```

The launcher creates a Python virtual environment, installs lightweight backend dependencies, builds the frontend when needed, and starts the application.

**Local application:**

http://localhost:8000

The actual startup URL printed by the launcher should be treated as authoritative.

### Option 2 — Advanced Docker Stack

**Requirements:**

- Docker Desktop or Docker Engine.
- Docker Compose v2.
- Approximately 4 GB or more available RAM.
- Additional disk space for database and event-index storage.

On Linux, OpenSearch may require:

```bash
sudo sysctl -w vm.max_map_count=262144
```

Create the environment configuration:

```bash
cp .env.example .env
```

Set a strong `SECRET_KEY` and `POSTGRES_PASSWORD` in `.env`.

Start the stack:

```bash
docker compose up -d --build
```

Check service status:

```bash
docker compose ps
```

Follow backend and worker logs:

```bash
docker compose logs -f backend worker
```

**Application:**

http://localhost:8080

**API documentation in development mode:**

http://localhost:8080/api/docs

API documentation is disabled when `APP_ENV=production`.

For detailed configuration, administrator bootstrap, and troubleshooting, see [`SETUP.md`](SETUP.md).

### Demo Data

After starting the Docker stack:

**Windows:**

```bat
scripts\demo.bat
```

**Linux / macOS:**

```bash
./scripts/demo.sh
```

The demo workflow registers lab endpoints and replays synthetic security events. Demo accounts and their credentials are generated according to the demo script.

Use only the generated credentials displayed by the script. Demo accounts are not intended for production.

---

## Configuration

Configuration depends on the selected runtime.

Important environment variables include:

| Variable | Purpose |
|---|---|
| `APP_ENV` | Runtime environment |
| `SECRET_KEY` | Application signing and cryptographic secret |
| `DATABASE_URL` | Database connection |
| `QUEUE_BACKEND` | Queue implementation |
| `STORE_BACKEND` | Event storage implementation |
| `BOOTSTRAP_ADMIN_EMAIL` | Initial administrator email |
| `BOOTSTRAP_ADMIN_PASSWORD` | Optional initial administrator password |
| `CORS_ORIGINS` | Allowed browser origins |
| `EVENT_RETENTION_DAYS` | Event retention configuration |
| `COLLECTOR_KEY_TTL_DAYS` | Collector credential lifetime |
| `AI_PROVIDER` | Optional AI provider configuration |
| `AI_API_KEY` | Optional server-level AI credential |
| `AI_MODEL` | AI model configuration |
| `AI_BASE_URL` | Optional OpenAI-compatible provider endpoint |
| `MAIL_MODE` | Email delivery mode |
| `SMTP_HOST` | SMTP server |
| `SMTP_USER` | SMTP account |
| `SMTP_PASSWORD` | SMTP credential |
| `BREVO_API_KEY` | Optional Brevo API credential |
| `FRONTEND_BASE_URL` | Frontend URL used in account links |
| `SYSLOG_UDP_PORT` | Syslog UDP listener port |
| `SYSLOG_BIND` | Syslog bind address |

The actual variables available depend on the runtime configuration and application settings.

Never commit `.env`, API keys, database credentials, or other secrets to Git.

For the complete configuration reference, inspect `.env.example`, `.env.lite.example`, and the application configuration.

---

## API & Telemetry Ingestion

The ingestion API accepts authenticated event batches.

Example request:

```bash
curl -X POST "http://localhost:8000/api/v1/ingest/events/batch" \
  -H "X-API-Key: YOUR_COLLECTOR_KEY" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: batch-0001" \
  -d '{
    "events": [
      {
        "event_id": "ssh-event-001",
        "timestamp": "2026-11-14T12:00:00Z",
        "source_type": "linux_auth",
        "host": {
          "name": "LAB-LNX-01"
        },
        "raw": {
          "program": "sshd",
          "message": "Failed password for invalid user admin from 203.0.113.50 port 4242 ssh2"
        }
      }
    ]
  }'
```

Use an endpoint key created through the application. The example key is a placeholder.

See [`docs/INGESTION.md`](docs/INGESTION.md) for the event envelope, supported source types, and ingestion limits.

---

## Security Design

Security is a core design consideration throughout SentinelX.

Implemented security mechanisms include:

- Argon2id password hashing.
- JWT-based authentication.
- Refresh-token rotation and revocation.
- Role and permission-based authorization.
- Organization-level data isolation.
- Hashed collector credentials.
- Encrypted stored AI credentials.
- Single-use account verification and password-reset tokens.
- Request ID correlation.
- Request body-size limits.
- Security response headers.
- Structured application logging.
- Input validation and controlled error responses.
- Append-only audit-log protections.
- Approval checks for simulated response workflows.
- Secret scrubbing in relevant AI-provider error handling.

### Deployment Security Considerations

For any environment beyond a local lab:

1. Use HTTPS.
2. Set a strong, unique `SECRET_KEY`.
3. Protect database and AI credentials.
4. Restrict network access to internal services.
5. Disable public registration if it is not required.
6. Use a persistent and appropriately secured database.
7. Back up application data.
8. Monitor application logs and endpoint health.
9. Only register systems you own or are authorized to monitor.
10. Do not expose the Docker lab's unauthenticated OpenSearch configuration to untrusted networks.

Security controls and deployment configuration should be independently reviewed before production use.

---

## Deployment

The repository includes a single-container Dockerfile intended for hosted deployment.

The root Dockerfile:

- Builds the React frontend.
- Installs lightweight backend dependencies.
- Packages the backend and built frontend.
- Runs the application as a non-root user.
- Uses SQLite and an in-memory queue by default.

### Current Hosted Deployment

**Platform:** Render  
**Application:** https://sentinelx-v2-85pr.onrender.com

The current lightweight hosted configuration uses:

- SQLite.
- In-memory queue.
- SQLite-backed event storage.
- Single-container application deployment.

**Important persistence limitation:** Render Free services use an ephemeral filesystem unless persistent storage is separately configured. SQLite data stored on that filesystem may be lost after a restart, redeployment, or instance replacement. The current deployment should therefore be treated as a demonstration environment, not a durable production data store.

The advanced Docker Compose stack is a separate deployment configuration and uses PostgreSQL, Redis, and OpenSearch.

---

## Testing & Verification

The project includes automated tests covering core domain behavior, detection, ingestion, authentication logic, agent processing, and related security workflows.

According to the project's development verification report:

| Verification area | Status |
|---|---|
| Core domain unit tests | 79 executed and passed during development |
| Detection rule engine | Executed test coverage |
| Event normalization | Executed test coverage |
| Tenant and rule-state isolation logic | Executed test coverage |
| AI provider client behavior against a local fake server | Executed test coverage |
| Agent parsing and spool/retry logic | Executed test coverage |
| API integration test suites | Written, not executed in the documented authoring environment |
| Real external AI-provider calls | Not verified |
| Real Windows Event Log collection | Not verified on a real host |
| Real Linux journald collection | Not verified on a real host |
| PostgreSQL deployment path | Not verified in the documented development environment |
| Frontend rendering and full browser E2E | Not verified in the documented development environment |

These statuses describe the project's documented development verification. They are not a claim that every test has been executed against the current hosted deployment.

For more details, see [`docs/REQUIREMENTS_COVERAGE.md`](docs/REQUIREMENTS_COVERAGE.md) and [`docs/ENHANCEMENT_REPORT.md`](docs/ENHANCEMENT_REPORT.md).

---

## Known Limitations

SentinelX is actively developed and has the following known limitations:

- Designed for lab-scale and educational use.
- Hosted lightweight mode uses SQLite and an in-memory queue.
- SQLite is not intended for high-concurrency, multi-node production workloads.
- In-memory queue state does not provide durable queue persistence.
- Render Free filesystem storage is ephemeral.
- The Docker OpenSearch security plugin is disabled for the local lab stack.
- Response Center actions are simulated only.
- No real endpoint isolation or firewall response adapter is implemented.
- DNS-specific parsing is not implemented.
- NetFlow/IPFIX ingestion is not implemented.
- Windows and Linux endpoint collection require validation on actual target systems.
- AI analysis depends on external provider availability and configuration.
- AI output can be incomplete or incorrect and requires analyst review.
- Rate limiting is process-local in the current implementation.
- The project does not claim full MITRE ATT&CK coverage.
- Enterprise SSO, MFA, and browser-based end-to-end test coverage are not claimed as implemented.

---

## Responsible Use

SentinelX is intended for authorized defensive security monitoring, research, testing, and educational demonstrations.

Only connect endpoints, network devices, and infrastructure that you own or are explicitly authorized to monitor.

Do not use the platform to access, monitor, test, or interfere with systems without permission.

Synthetic events and lab endpoints are recommended when evaluating detection workflows.

The author is not responsible for unauthorized use or damage resulting from misuse of the software.

---

## Roadmap

Potential future development areas include:

- Expanded endpoint telemetry coverage.
- Additional Windows and Linux event sources.
- More detection rules and improved rule testing.
- Persistent distributed queue processing.
- Improved event-search scalability.
- Expanded incident investigation workflows.
- Additional provider integrations.
- Multi-factor authentication.
- Enterprise identity integration.
- Browser-based end-to-end testing.
- Advanced threat hunting and correlation.
- More comprehensive deployment and backup tooling.
- Additional response integrations after security review.

Roadmap items are proposals, not claims of current implementation.

---

## Documentation

| Document | Description |
|---|---|
| [`SETUP.md`](SETUP.md) | Installation and setup |
| [`START-HERE.txt`](START-HERE.txt) | Simplified startup guide |
| [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | Common problems and fixes |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Technical architecture |
| [`docs/AGENT.md`](docs/AGENT.md) | Endpoint agent setup |
| [`docs/INGESTION.md`](docs/INGESTION.md) | Telemetry ingestion |
| [`docs/REQUIREMENTS_COVERAGE.md`](docs/REQUIREMENTS_COVERAGE.md) | Requirement and test coverage |
| [`docs/ENHANCEMENT_REPORT.md`](docs/ENHANCEMENT_REPORT.md) | Version 2.0 development report |
| [`sample-data/README.md`](sample-data/README.md) | Sample event data |

---

## Author

**Saud Nadaf**

Cybersecurity-focused B.Tech student at Darbhanga College of Engineering, Bihar.

Interested in security engineering, vulnerability assessment, web and application security, security operations, digital forensics, and defensive security tooling.

**Project:** SentinelX

- GitHub: https://github.com/saudnadaf09
- LinkedIn: https://www.linkedin.com/in/saud-nadaf-41b015343/
- Email: saudnadaf.infosec@proton.me

---

## License

SentinelX is licensed under the **MIT License**.

See the [`LICENSE`](LICENSE) file for the complete license text.

Copyright (c) 2026 Saud Nadaf.

Third-party dependencies and referenced materials remain subject to their respective licenses and terms.
