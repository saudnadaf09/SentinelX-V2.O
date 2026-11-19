"""Multi-tenancy, registration and AI settings (idempotent: safe on legacy v1 databases AND fresh ones).

Legacy databases (created by 0001 before this change) get the new tables/columns added; every existing
row is preserved and assigned to the 'Default Workspace' organization. Existing 'admin' users become
'super_admin'. Fresh databases (where 0001 already created the new schema) only get the default org.
"""
import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

from app.domain.tenancy import DEFAULT_ORG_ID
from app.models import Base

revision = "0002_multitenancy"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

NEW_TABLES = ["organizations", "auth_tokens", "org_rule_overrides", "ai_settings"]
COLUMNS = {  # table -> [(name, type, server_default)]
    "users": [("username", sa.String(32), None), ("org_id", sa.Uuid(), None), ("email_verified", sa.Boolean(), sa.false())],
    "refresh_tokens": [("ip", sa.String(64), None), ("user_agent", sa.String(200), None)],
    "assets": [("org_id", sa.Uuid(), None), ("data_class", sa.String(12), sa.text("'live'")),
               ("agent_version", sa.String(64), None), ("os_version", sa.String(120), None),
               ("ip_address", sa.String(64), None), ("source_ip", sa.String(64), None),
               ("collection_status", sa.JSON(), None), ("last_heartbeat_at", sa.DateTime(timezone=True), None),
               ("enrolled_at", sa.DateTime(timezone=True), None), ("deregistered_at", sa.DateTime(timezone=True), None)],
    "alerts": [("org_id", sa.Uuid(), None), ("data_class", sa.String(12), sa.text("'live'"))],
    "organizations": [("retention_days", sa.Integer(), None)],
    "detection_rules": [("org_id", sa.Uuid(), None)],
    "incidents": [("org_id", sa.Uuid(), None)],
    "response_actions": [("org_id", sa.Uuid(), None)],
    "audit_logs": [("org_id", sa.Uuid(), None)],
}
ORG_INDEXES = ["users", "assets", "alerts", "incidents", "response_actions", "audit_logs", "detection_rules"]


def upgrade() -> None:
    bind = op.get_bind()
    for name in NEW_TABLES:
        Base.metadata.tables[name].create(bind, checkfirst=True)

    insp = sa.inspect(bind)
    for table, cols in COLUMNS.items():
        have = {c["name"] for c in insp.get_columns(table)}
        for name, typ, default in cols:
            if name not in have:
                op.add_column(table, sa.Column(name, typ, nullable=True if default is None else False,
                                               server_default=default))
    insp = sa.inspect(bind)

    def has_index(table, name):
        return name in {i["name"] for i in insp.get_indexes(table)}

    for table in ORG_INDEXES:
        if not has_index(table, f"ix_{table}_org_id"):
            op.create_index(f"ix_{table}_org_id", table, ["org_id"])
    if not has_index("users", "ix_users_username"):
        op.create_index("ix_users_username", "users", ["username"], unique=True)

    # hostname was globally unique; it is now unique per organization
    idx = {i["name"]: i for i in insp.get_indexes("assets")}
    if "ix_assets_hostname" in idx and idx["ix_assets_hostname"].get("unique"):
        op.drop_index("ix_assets_hostname", table_name="assets")
        op.create_index("ix_assets_hostname", "assets", ["hostname"])

    # default organization + backfill of legacy rows
    org = sa.table("organizations", sa.column("id", sa.Uuid()), sa.column("name", sa.String), sa.column("slug", sa.String),
                   sa.column("kind", sa.String), sa.column("details", sa.String), sa.column("is_active", sa.Boolean),
                   sa.column("created_at", sa.DateTime(timezone=True)))
    default_id = uuid.UUID(DEFAULT_ORG_ID)
    if not bind.execute(sa.select(org.c.id).where(org.c.id == default_id)).first():
        bind.execute(org.insert().values(id=default_id, name="Default Workspace", slug="default-workspace",
                                         kind="organization", details="Created by migration 0002 for pre-existing data.",
                                         is_active=True, created_at=datetime.now(timezone.utc)))
    users = sa.table("users", sa.column("org_id", sa.Uuid()), sa.column("role", sa.String), sa.column("email_verified", sa.Boolean()))
    bind.execute(users.update().where(users.c.role == "admin").values(role="super_admin"))
    bind.execute(users.update().where(users.c.org_id.is_(None)).values(org_id=default_id, email_verified=True))
    for t in ("assets", "alerts", "incidents", "response_actions"):  # audit_logs is append-only: NULL means default org
        tbl = sa.table(t, sa.column("org_id", sa.Uuid()))
        bind.execute(tbl.update().where(tbl.c.org_id.is_(None)).values(org_id=default_id))

    # classify legacy data accurately where its origin is known: everything seeded by the demo replay is SIMULATED
    assets = sa.table("assets", sa.column("id", sa.Uuid()), sa.column("tags", sa.JSON()), sa.column("data_class", sa.String),
                      sa.column("collection_status", sa.JSON()))
    demo_ids = []
    for row in bind.execute(sa.select(assets.c.id, assets.c.tags)):
        if isinstance(row.tags, list) and ("demo" in row.tags or "synthetic" in row.tags):
            demo_ids.append(row.id)
    if demo_ids:
        bind.execute(assets.update().where(assets.c.id.in_(demo_ids)).values(data_class="simulated"))
    alerts = sa.table("alerts", sa.column("asset_id", sa.Uuid()), sa.column("data_class", sa.String))
    if demo_ids:
        bind.execute(alerts.update().where(alerts.c.asset_id.in_(demo_ids)).values(data_class="simulated"))
    bind.execute(alerts.update().where(alerts.c.asset_id.is_(None)).values(data_class="unclassified"))
    bind.execute(assets.update().where(assets.c.collection_status.is_(None)).values(collection_status={}))

    insp = sa.inspect(bind)
    if "uq_assets_org_hostname" not in {i["name"] for i in insp.get_indexes("assets")}:
        op.create_index("uq_assets_org_hostname", "assets", ["org_id", "hostname"], unique=True)

    if bind.dialect.name == "sqlite":  # PostgreSQL already has its append-only trigger from 0001
        for name, event in (("audit_logs_no_update", "UPDATE"), ("audit_logs_no_delete", "DELETE")):
            op.execute(f"CREATE TRIGGER IF NOT EXISTS {name} BEFORE {event} ON audit_logs "
                       "BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END;")


def downgrade() -> None:
    # Data-preserving downgrade is intentionally not provided: restore from a backup of backend/data instead.
    raise NotImplementedError("downgrade of 0002_multitenancy is not supported; restore a backup")
