"""Hosted entry point (Render etc.): migrate, create admin from env, load demo data, serve on $PORT."""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.chdir(HERE)
sys.path.insert(0, str(HERE))
(HERE / "data").mkdir(exist_ok=True)

if not os.environ.get("BOOTSTRAP_ADMIN_PASSWORD"):
    print("WARNING: BOOTSTRAP_ADMIN_PASSWORD is not set; a random admin password will be printed once below.")


def main() -> None:
    from alembic import command
    from alembic.config import Config

    from app.cli import cmd_bootstrap, cmd_replay

    cfg = Config(str(HERE / "alembic.ini"))
    cfg.set_main_option("script_location", str(HERE / "alembic"))
    command.upgrade(cfg, "head")
    cmd_bootstrap(None)  # creates the admin only if no users exist yet

    marker = HERE / "data" / ".demo_loaded"
    if os.environ.get("LOAD_DEMO_DATA", "true").lower() == "true" and not marker.exists():
        class Args:
            file = None
        cmd_replay(Args())  # synthetic data only
        marker.write_text("ok")

    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=int(os.environ.get("PORT", "10000")),
                proxy_headers=True, forwarded_allow_ips="*", log_level="warning")


if __name__ == "__main__":
    main()
