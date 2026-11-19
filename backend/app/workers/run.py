"""Worker entry point: python -m app.workers.run"""
from __future__ import annotations

import socket

from app.core.config import get_settings
from app.core.container import get_queue, get_registry, get_store
from app.core.logging import setup_logging
from app.workers.pipeline import Pipeline


def main() -> None:
    s = get_settings()
    setup_logging(s.log_level)
    queue, store = get_queue(), get_store()
    queue.ensure_ready()
    store.ensure_ready()
    Pipeline(queue, store, get_registry()).run_forever(consumer=f"worker-{socket.gethostname()}")


if __name__ == "__main__":
    main()
