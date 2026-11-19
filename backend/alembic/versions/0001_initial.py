"""Baseline schema.

The baseline creates every table from the SQLAlchemy models as they stood at v1.0.0
(``Base.metadata.create_all``). Later schema changes MUST be explicit migrations
(``alembic revision --autogenerate`` against a live PostgreSQL), not edits to this file.
It also installs an append-only guard on audit_logs for PostgreSQL.
"""
from alembic import op

from app.models import Base

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind)
    if bind.dialect.name == "postgresql":
        op.execute("""
            CREATE OR REPLACE FUNCTION sx_audit_append_only() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'audit_logs is append-only';
            END;
            $$ LANGUAGE plpgsql;
        """)
        op.execute("""
            CREATE TRIGGER audit_logs_append_only BEFORE UPDATE OR DELETE ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION sx_audit_append_only();
        """)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs")
        op.execute("DROP FUNCTION IF EXISTS sx_audit_append_only()")
    Base.metadata.drop_all(bind)
