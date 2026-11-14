"""Cola de trabajos sobre la tabla `scans` (PostgreSQL `FOR UPDATE SKIP LOCKED`).

PostgreSQL documenta `SKIP LOCKED` para tablas tipo cola con varios consumidores.
En SQLite (tests) se usa un equivalente sin bloqueo de filas.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import select, text, update

from ..extensions import db
from ..models.entities import Scan, ScanUpload, utcnow

CLAIM_SQL = text("""
UPDATE scans
   SET status = 'running', started_at = now(), heartbeat_at = now(), worker_id = :worker, attempts = attempts + 1
 WHERE id = (SELECT id FROM scans WHERE status = 'queued' ORDER BY queued_at FOR UPDATE SKIP LOCKED LIMIT 1)
RETURNING id
""")


def claim(worker_id: str) -> uuid.UUID | None:
    if db.engine.dialect.name == "postgresql":
        row = db.session.execute(CLAIM_SQL, {"worker": worker_id}).first()
        db.session.commit()
        return row[0] if row else None
    scan = db.session.scalars(select(Scan).where(Scan.status == "queued").order_by(Scan.queued_at).limit(1)).first()
    if scan is None:
        return None
    now = utcnow()
    scan.status, scan.started_at, scan.heartbeat_at = "running", now, now
    scan.worker_id, scan.attempts = worker_id, scan.attempts + 1
    db.session.commit()
    return scan.id


def heartbeat(scan_id: uuid.UUID, done: int | None = None, total: int | None = None) -> bool:
    """Actualiza el latido y el progreso. Devuelve True si se pidió cancelar."""
    values: dict = {"heartbeat_at": utcnow()}
    if done is not None:
        values["progress_done"] = done
    if total is not None:
        values["progress_total"] = total
    db.session.execute(update(Scan).where(Scan.id == scan_id).values(**values))
    db.session.commit()
    return bool(db.session.scalar(select(Scan.cancel_requested).where(Scan.id == scan_id)))


def reap(stale_after: timedelta = timedelta(minutes=2), max_attempts: int = 3) -> tuple[int, int]:
    """Devuelve a la cola los escaneos de workers caídos; tras `max_attempts`, los marca fallidos."""
    limit = utcnow() - stale_after
    stale = list(db.session.scalars(select(Scan).where(Scan.status == "running", Scan.heartbeat_at < limit)))
    requeued = failed = 0
    for scan in stale:
        if scan.attempts < max_attempts and not scan.cancel_requested:
            scan.status, scan.worker_id, scan.started_at = "queued", None, None
            requeued += 1
        else:
            scan.status = "canceled" if scan.cancel_requested else "failed"
            scan.error_code = None if scan.cancel_requested else "worker_lost"
            scan.finished_at = utcnow()
            upload = db.session.get(ScanUpload, scan.id)
            if upload is not None:
                db.session.delete(upload)
            failed += 1
    db.session.commit()
    return requeued, failed
