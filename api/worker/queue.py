"""Cola de trabajos sobre la tabla `scans` (PostgreSQL `FOR UPDATE SKIP LOCKED`).

PostgreSQL documenta `SKIP LOCKED` para tablas tipo cola con varios consumidores.
En SQLite (tests) se usa un equivalente sin bloqueo de filas.
"""

from __future__ import annotations

import uuid
from datetime import timedelta, timezone

from sqlalchemy import func, select, text, update

from ..extensions import db
from ..models.entities import Scan, ScanUpload, utcnow

# Orden de la cola (el mismo en SQL y en Python):
#   1. Prioridad: código pegado primero, luego ZIP pequeños, luego el resto (ZIP grandes y
#      GitHub). Un escaneo que lleva más de AGING esperando sube a la prioridad más alta, para
#      que un repositorio grande no espere para siempre detrás de escaneos rápidos.
#   2. Turno: entre iguales, primero el usuario al que hace más tiempo que no se atiende (o al
#      que nunca se atendió). Así nadie acapara el único worker con muchos escaneos.
#   3. Orden de llegada.
AGING = timedelta(minutes=5)
SMALL_ZIP_BYTES = 1024 * 1024

CLAIM_SQL = text("""
UPDATE scans
   SET status = 'running', started_at = now(), heartbeat_at = now(), worker_id = :worker, attempts = attempts + 1
 WHERE id = (
    SELECT s.id
      FROM scans s
      LEFT JOIN scan_uploads u ON u.scan_id = s.id
     WHERE s.status = 'queued'
     ORDER BY CASE WHEN s.queued_at < now() - make_interval(secs => :aging) THEN 0
                   WHEN s.source = 'snippet' THEN 0
                   WHEN s.source = 'zip' AND u.size < :small THEN 1
                   ELSE 2 END,
              (SELECT max(p.started_at) FROM scans p WHERE p.created_by = s.created_by) NULLS FIRST,
              s.queued_at
       FOR UPDATE OF s SKIP LOCKED
     LIMIT 1)
RETURNING id
""")


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def queue_order() -> list[uuid.UUID]:
    """Escaneos en cola, en el orden en que se atenderán (versión Python de CLAIM_SQL)."""
    queued = list(db.session.execute(
        select(Scan.id, Scan.source, Scan.created_by, Scan.queued_at, ScanUpload.size)
        .outerjoin(ScanUpload, ScanUpload.scan_id == Scan.id).where(Scan.status == "queued")))
    if not queued:
        return []
    users = {r.created_by for r in queued}
    last_served = dict(db.session.execute(
        select(Scan.created_by, func.max(Scan.started_at)).where(Scan.created_by.in_(users))
        .group_by(Scan.created_by)).all())
    now = utcnow()

    def priority(r) -> int:
        if _aware(r.queued_at) < now - AGING or r.source == "snippet":
            return 0
        return 1 if r.source == "zip" and (r.size or 0) < SMALL_ZIP_BYTES else 2

    def key(r):
        served = _aware(last_served.get(r.created_by))
        # NULLS FIRST: nunca atendido va delante; después, el que hace más tiempo.
        return (priority(r), served is not None, served or now, _aware(r.queued_at))

    return [r.id for r in sorted(queued, key=key)]


def claim_params(worker_id: str) -> dict:
    return {"worker": worker_id, "aging": AGING.total_seconds(), "small": SMALL_ZIP_BYTES}


def claim(worker_id: str) -> uuid.UUID | None:
    if db.engine.dialect.name == "postgresql":
        row = db.session.execute(CLAIM_SQL, claim_params(worker_id)).first()
        db.session.commit()
        return row[0] if row else None
    order = queue_order()
    if not order:
        return None
    scan = db.session.get(Scan, order[0])
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


DEFAULT_SCAN_S = 30          # estimación si aún no hay escaneos terminados con los que medir


def typical_duration_s(sample: int = 20) -> float:
    """Mediana de la duración de los últimos escaneos terminados (robusta ante uno muy largo)."""
    rows = db.session.execute(
        select(Scan.started_at, Scan.finished_at)
        .where(Scan.status == "done", Scan.started_at.is_not(None), Scan.finished_at.is_not(None))
        .order_by(Scan.finished_at.desc()).limit(sample)).all()
    durations = sorted((_aware(f) - _aware(s)).total_seconds() for s, f in rows)
    if not durations:
        return DEFAULT_SCAN_S
    mid = len(durations) // 2
    return durations[mid] if len(durations) % 2 else (durations[mid - 1] + durations[mid]) / 2


def position(scan: Scan) -> dict | None:
    """Para un escaneo en cola: cuántos se atenderán antes y una estimación de la espera.

    Hay un solo worker, así que el que está en curso también cuenta como «delante».
    """
    if scan.status != "queued":
        return None
    order = queue_order()
    if scan.id not in order:
        return None
    running = db.session.scalar(select(func.count()).select_from(Scan).where(Scan.status == "running")) or 0
    ahead = order.index(scan.id) + running
    return {"ahead": ahead, "eta_s": int(round((ahead + 1) * typical_duration_s()))}
