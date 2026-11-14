"""Worker de escaneos:  python -m api.worker

Bucle: reaper (trabajos de workers caídos) -> reclamar con SKIP LOCKED ->
procesar en un proceso hijo -> repetir. Termina limpio con SIGTERM/SIGINT.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
import time

from sast import __version__
from sast.rules.registry import default_ruleset

from ..extensions import db
from ..factory import create_app
from ..services.issue_service import sync_rules
from . import queue
from .runner import process, purge

log = logging.getLogger("api.worker")
_stop = False


def _handle_stop(signum, _frame):  # pragma: no cover
    global _stop
    _stop = True
    log.info("señal %s recibida: termino tras el trabajo actual", signum)


def main() -> None:  # pragma: no cover - bucle de proceso
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    app = create_app()
    settings = app.config["SETTINGS"]
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    with app.app_context():
        sync_rules(default_ruleset(), __version__)
        db.session.commit()
        log.info("worker listo", extra={"worker_id": worker_id})
        last_reap = last_purge = 0.0
        while not _stop:
            now = time.monotonic()
            if now - last_reap > 30:
                queue.reap()
                last_reap = now
            if now - last_purge > 3600:
                purge(settings.retention_days)
                last_purge = now
            scan_id = queue.claim(worker_id)
            if scan_id is None:
                time.sleep(1.0)
                continue
            process(scan_id, settings)
            db.session.remove()


if __name__ == "__main__":  # pragma: no cover
    main()
