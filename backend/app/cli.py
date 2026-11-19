"""Local administration CLI:  python -m app.cli <command>

  bootstrap             create the first admin from BOOTSTRAP_ADMIN_* (random password if unset)
  seed-demo-users       create analyst/engineer/viewer demo users with RANDOM passwords (not in production)
  replay-sample         register lab assets and ingest the synthetic attack scenario
  create-collector-key  issue a collector API key for an asset
  export-sample         write the synthetic scenario to a JSONL file
  requeue-dead-letters  move dead-lettered events back onto the queue
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import uuid
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select

from app.core import security
from app.core.config import get_settings
from app.core.container import get_queue, get_registry, get_store
from app.core.logging import setup_logging
from app.db.base import utcnow
from app.db.session import get_session_factory
from app.domain.tenancy import DEFAULT_ORG_ID
from app.models import ApiKey, Asset, User
from app.samples import LNX, WIN, build_scenario, write_jsonl
from app.services import audit, org_service, rule_service
from app.services.ingest_service import ingest_batch

PLATFORMS = {WIN: "windows", LNX: "linux"}


def _new_password() -> str:
    return secrets.token_urlsafe(18)


def cmd_bootstrap(_args) -> int:
    s = get_settings()
    with get_session_factory()() as db:
        if db.scalar(select(User.id).limit(1)):
            print("bootstrap: users already exist; nothing to do")
            return 0
        email = s.bootstrap_admin_email.strip().lower()
        password, generated = s.bootstrap_admin_password, False
        if not password:
            password, generated = _new_password(), True
        try:
            security.validate_password_strength(password)
        except ValueError as exc:
            print(f"bootstrap: BOOTSTRAP_ADMIN_PASSWORD rejected: {exc}", file=sys.stderr)
            return 1
        org_service.ensure_default_org(db)
        # the only way to create a platform administrator: this local bootstrap (never public registration)
        user = User(email=email, username="admin", full_name="Administrator", role="super_admin", org_id=uuid.UUID(DEFAULT_ORG_ID),
                    email_verified=True, password_hash=security.hash_password(password))
        db.add(user)
        db.flush()
        audit.record(db, actor=None, actor_email="bootstrap", action="user.bootstrap_admin", target_type="user",
                     target_id=str(user.id), details={"email": email})
        db.commit()
        print(f"bootstrap: created admin {email}")
        if generated:
            print(f"bootstrap: generated password (shown once): {password}")
    return 0


def cmd_seed_demo_users(_args) -> int:
    if get_settings().is_production:
        print("refusing to create demo users when APP_ENV=production", file=sys.stderr)
        return 1
    created = []
    with get_session_factory()() as db:
        for role in ("analyst", "engineer", "viewer"):
            email = f"{role}@sentinelx.local"
            if db.scalar(select(User).where(User.email == email)):
                continue
            pw = _new_password()
            db.add(User(email=email, username=role, full_name=f"Demo {role.title()}", role=role, org_id=uuid.UUID(DEFAULT_ORG_ID),
                        email_verified=True, password_hash=security.hash_password(pw)))
            created.append((email, pw))
        db.commit()
    if not created:
        print("demo users already exist (passwords are not recoverable; reset them from Settings > Users)")
    for email, pw in created:
        print(f"{email}  password: {pw}")
    return 0


def _ensure_asset(db, hostname: str) -> Asset:
    org_id = uuid.UUID(DEFAULT_ORG_ID)
    a = db.scalar(select(Asset).where(Asset.hostname == hostname, Asset.org_id == org_id))
    if a is None:  # demo endpoints are labelled SIMULATED everywhere in the UI
        a = Asset(org_id=org_id, hostname=hostname, platform=PLATFORMS.get(hostname, "linux"), is_lab_authorized=True,
                  tags=["demo", "synthetic"], owner="SentinelX demo", data_class="simulated")
        db.add(a)
        db.flush()
    return a


def cmd_replay(args) -> int:
    queue, store = get_queue(), get_store()
    queue.ensure_ready()
    store.ensure_ready()
    with get_session_factory()() as db:
        rule_service.seed_mitre(db)
        rule_service.seed_rules_from_files(db, Path(get_settings().rules_dir))
        if args.file:
            scenario: dict[str, list] = {}
            for line in Path(args.file).read_text(encoding="utf-8").splitlines():
                if line.strip():
                    row = json.loads(line)
                    scenario.setdefault(row["asset"], []).append(row["envelope"])
        else:
            scenario = build_scenario(prefix=f"demo-{uuid.uuid4().hex[:6]}")
        total = 0
        for host, events in scenario.items():
            asset = _ensure_asset(db, host)
            res = ingest_batch(db, queue=queue, asset=asset, key=None, events=events, idempotency_key=None,
                               request_id=f"replay-{uuid.uuid4().hex[:8]}")
            total += res["accepted"]
            print(f"{host}: accepted={res['accepted']} rejected={res['rejected']}")
    if queue.kind == "memory":
        from app.workers.pipeline import Pipeline
        reg = get_registry()
        reg.reload()
        Pipeline(queue, store, reg).drain()
    print(f"replayed {total} synthetic events. With Docker the worker processes them within seconds.")
    return 0


def cmd_collector_key(args) -> int:
    with get_session_factory()() as db:
        asset = db.scalar(select(Asset).where(Asset.hostname == args.hostname, Asset.org_id == uuid.UUID(DEFAULT_ORG_ID)))
        if asset is None:
            print(f"asset {args.hostname!r} not found; register it first", file=sys.stderr)
            return 1
        full, prefix, digest = security.generate_api_key()
        db.add(ApiKey(asset_id=asset.id, name=args.name, prefix=prefix, key_hash=digest,
                       expires_at=utcnow() + timedelta(days=get_settings().collector_key_ttl_days)))
        db.commit()
    print(f"API key (shown once): {full}")
    return 0


def cmd_export(args) -> int:
    n = write_jsonl(args.out, build_scenario(prefix="sample"))
    print(f"wrote {n} events to {args.out}")
    return 0


def cmd_requeue(_args) -> int:
    print(f"requeued {get_queue().requeue_dead_letters()} dead-lettered events")
    return 0


def main(argv: list[str] | None = None) -> int:
    setup_logging("WARNING")
    p = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("bootstrap").set_defaults(fn=cmd_bootstrap)
    sub.add_parser("seed-demo-users").set_defaults(fn=cmd_seed_demo_users)
    r = sub.add_parser("replay-sample")
    r.add_argument("--file", help="JSONL produced by export-sample (default: generate fresh timestamps)")
    r.set_defaults(fn=cmd_replay)
    k = sub.add_parser("create-collector-key")
    k.add_argument("--hostname", required=True)
    k.add_argument("--name", default="cli-key")
    k.set_defaults(fn=cmd_collector_key)
    e = sub.add_parser("export-sample")
    e.add_argument("--out", default="sample-data/sample_events.jsonl")
    e.set_defaults(fn=cmd_export)
    sub.add_parser("requeue-dead-letters").set_defaults(fn=cmd_requeue)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
