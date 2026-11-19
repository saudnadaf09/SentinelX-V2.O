"""FastAPI application factory."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.core.config import get_settings
from app.core.container import get_queue, get_registry, get_store
from app.core.errors import AppError
from app.core.logging import setup_logging
from app.core.middleware import RequestContextMiddleware
from app.db.session import get_session_factory

log = logging.getLogger("sentinelx")


def _rid(request: Request) -> str:
    return request.scope.get("state", {}).get("request_id", "")


def _err(status: int, code: str, message: str, request: Request, details=None) -> JSONResponse:
    body = {"error": {"code": code, "message": message, "request_id": _rid(request)}}
    if details:
        body["error"]["details"] = details
    return JSONResponse(body, status_code=status)


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.services import org_service, rule_service
    s = get_settings()
    setup_logging(s.log_level)
    get_queue().ensure_ready()
    get_store().ensure_ready()
    with get_session_factory()() as db:
        rule_service.seed_mitre(db)
        rule_service.seed_rules_from_files(db, __import__("pathlib").Path(s.rules_dir))
    with get_session_factory()() as db:
        org_service.ensure_default_org(db)
        db.commit()
    if get_store().kind != "opensearch":  # no worker process in Easy Mode, so prune here
        _apply_retention(s)
    _start_syslog(s)
    n = get_registry().reload()
    log.info("sentinelx started", extra={"version": __version__, "rules": n, "queue": s.queue_backend,
                                        "store": s.store_backend})
    yield


def _apply_retention(s) -> None:
    """Per-organization retention (falls back to the platform default)."""
    from sqlalchemy import select

    from app.models import Organization
    store = get_store()
    with get_session_factory()() as db:
        for org in db.scalars(select(Organization)):
            store.delete_older_than(org.retention_days or s.event_retention_days, str(org.id))


def _start_syslog(s) -> None:
    if not s.syslog_udp_port:
        return
    from sqlalchemy import select

    from app.core.ratelimit import limiter
    from app.ingest.syslog_listener import SyslogServer, handle_datagram
    from app.models import Asset
    from app.db.base import utcnow
    from app.workers.pipeline import Pipeline

    queue, store = get_queue(), get_store()

    def resolve(ip: str):
        with get_session_factory()() as db:
            a = db.scalar(select(Asset).where(Asset.source_ip == ip, Asset.deregistered_at.is_(None)))
            return None if a is None else {"id": str(a.id), "org_id": str(a.org_id), "hostname": a.hostname, "data_class": a.data_class}

    def publish(asset: dict, payload: dict) -> None:
        queue.publish([payload])
        with get_session_factory()() as db:
            a = db.get(Asset, __import__("uuid").UUID(asset["id"]))
            if a is not None:
                a.last_seen_at = utcnow()
                a.events_received = (a.events_received or 0) + 1
                db.commit()
        if queue.kind == "memory":
            Pipeline(queue, store, get_registry()).drain()

    def on_datagram(data: bytes, ip: str) -> str:
        return handle_datagram(data, ip, resolve_asset=resolve, publish=publish, count=queue.incr,
                               allow=lambda k: limiter.allow(f"syslog:{k}", 600))

    server = SyslogServer(s.syslog_bind, s.syslog_udp_port, on_datagram).start()
    log.info("syslog UDP listener started", extra={"bind": s.syslog_bind, "port": server.port})


def create_app() -> FastAPI:
    s = get_settings()  # fails fast on a missing/weak SECRET_KEY
    docs = not s.is_production
    app = FastAPI(title="SentinelX API", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs" if docs else None, redoc_url=None,
                  openapi_url="/api/openapi.json" if docs else None)
    app.add_middleware(CORSMiddleware, allow_origins=s.cors_list, allow_credentials=False,
                       allow_methods=["GET", "POST", "PATCH", "DELETE"],
                       allow_headers=["Authorization", "Content-Type", "X-API-Key", "Idempotency-Key"])
    app.add_middleware(RequestContextMiddleware, max_body_bytes=s.max_body_bytes)

    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError):
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        resp = _err(exc.status, exc.code, exc.message, request)
        if headers:
            resp.headers.update(headers)
        return resp

    @app.exception_handler(HTTPException)
    async def _http(request: Request, exc: HTTPException):
        return _err(exc.status_code, "http_error", str(exc.detail), request)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        details = [{"field": ".".join(str(p) for p in e["loc"] if p != "body"), "message": e["msg"]}
                   for e in exc.errors()[:10]]  # never echo submitted values
        return _err(400, "validation_error", "Request validation failed", request, details)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        log.exception("unhandled error")
        return _err(500, "internal_error", "Internal server error", request)

    from app.api.v1 import (agent, ai, alerts, assets, audit, auth, dashboard, events, incidents, ingest, mitre, org,
                            platform, reports, response, rules, system, users)
    for module in (system, auth, users, org, platform, assets, agent, ingest, events, alerts, incidents, rules, mitre, ai,
                   response, audit, dashboard, reports):
        app.include_router(module.router, prefix="/api/v1")

    _mount_frontend(app, s.frontend_dist)
    return app


def _mount_frontend(app: FastAPI, dist_dir: str) -> None:
    """Easy Mode: serve the built React app from the same server (no Nginx needed)."""
    from pathlib import Path

    from fastapi.responses import FileResponse
    dist = Path(dist_dir).resolve() if dist_dir else None
    if not dist or not (dist / "index.html").is_file():
        return

    @app.get("/{full_path:path}", include_in_schema=False)
    def web_app(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found")
        target = (dist / full_path).resolve()
        if full_path and dist in target.parents and target.is_file():  # no path traversal outside dist
            return FileResponse(target)
        return FileResponse(dist / "index.html")


app = create_app()
