"""Ejecución aislada de un escaneo (RNF-01/RNF-04).

Cada escaneo corre en un proceso hijo con límite de tiempo real. Al llegar al límite, el
hijo deja de analizar y devuelve lo hecho (resultado parcial); si aun así no responde, se
termina. El código subido nunca se ejecuta: solo se lee como texto.

Antes de analizar se consulta la caché por contenido (`services.result_cache`).
"""

from __future__ import annotations

import logging
import multiprocessing as mp
import time
import uuid
from datetime import timedelta
from typing import Callable

from sqlalchemy import delete

from sast import __version__
from sast.engine.runner import Engine, ScanReport
from sast.rules.registry import default_ruleset

from ..extensions import db
from ..models.entities import Scan, ScanUpload, utcnow
from ..services import audit, issue_service, result_cache
from ..services.archive import ArchiveError, Limits, read_zip
from ..services.github_fetch import GitHubError, download_zipball, parse_repo
from . import queue

log = logging.getLogger("api.worker")
HEARTBEAT_EVERY = 2.0
SOFT_MARGIN_S = 15      # el hijo para antes del límite para devolver lo que lleva
HARD_GRACE_S = 30       # si no ha parado tras el límite, se le termina sin resultado


class ScanTimeout(Exception):
    pass


class ScanCanceledByUser(Exception):
    pass


def _child(conn, files: list[tuple[str, str]], rule_ids: list[str] | None,
           apply_excludes: bool = True, budget_s: float | None = None) -> None:  # pragma: no cover - proceso hijo
    try:
        ruleset = default_ruleset() if rule_ids is None else default_ruleset().select(ids=rule_ids)
        engine = Engine(ruleset)
        deadline = time.monotonic() + budget_s if budget_s is not None else None
        report = engine.scan_files(files, progress=lambda d, t: conn.send(("progress", d, t)),
                                   apply_excludes=apply_excludes, deadline=deadline)
        del files
        # Al padre solo le hace falta el código de los archivos con hallazgos: devolverlo todo
        # duplicaba en memoria el repositorio entero.
        report.prune_sources()
        conn.send(("done", report))
    except Exception as exc:  # el padre solo recibe el tipo, no datos del código
        conn.send(("error", type(exc).__name__))
    finally:
        conn.close()


def run_isolated(files: list[tuple[str, str]], rule_ids: list[str] | None, *, timeout_s: float,
                 on_tick: Callable[[int, int], bool], apply_excludes: bool = True,
                 release_input: bool = False) -> ScanReport:
    """Ejecuta el motor en un proceso hijo. `on_tick(done, total)` devuelve True para cancelar.

    El hijo para por sí mismo poco antes de `timeout_s` y devuelve un resultado parcial. Con
    `release_input`, la lista `files` se vacía en cuanto el hijo la ha recibido, para no tener
    el repositorio dos veces en memoria mientras dura el análisis.
    """
    ctx = mp.get_context("spawn")
    parent, child = ctx.Pipe(duplex=False)
    budget = max(timeout_s - SOFT_MARGIN_S, timeout_s * 0.8)
    proc = ctx.Process(target=_child, args=(child, files, rule_ids, apply_excludes, budget), daemon=True)
    total = len(files)
    proc.start()
    child.close()
    if release_input:
        files.clear()
    deadline = time.monotonic() + timeout_s + HARD_GRACE_S
    done = 0
    last_tick = 0.0
    try:
        while True:
            if parent.poll(0.25):
                try:
                    msg = parent.recv()
                except EOFError:
                    raise RuntimeError("el proceso de análisis terminó sin resultado") from None
                if msg[0] == "progress":
                    done, total = msg[1], msg[2]
                elif msg[0] == "done":
                    return msg[1]
                else:
                    raise RuntimeError(f"fallo del motor: {msg[1]}")
            now = time.monotonic()
            if now > deadline:
                raise ScanTimeout()
            if now - last_tick >= HEARTBEAT_EVERY:
                last_tick = now
                if on_tick(done, total):
                    raise ScanCanceledByUser()
            if not proc.is_alive() and not parent.poll(0):
                raise RuntimeError("el proceso de análisis terminó inesperadamente")
    finally:
        if proc.is_alive():
            proc.terminate()
        proc.join(timeout=5)
        parent.close()


def materialize(scan: Scan, upload: ScanUpload | None, settings) -> list[tuple[str, str]]:
    limits = Limits.from_settings(settings)
    if scan.source == "snippet":
        if upload is None:
            raise ArchiveError("missing_upload", "El contenido del escaneo ya no está disponible.")
        return [(upload.filename, upload.content.decode("utf-8", errors="replace"))]
    if scan.source == "zip":
        if upload is None:
            raise ArchiveError("missing_upload", "El contenido del escaneo ya no está disponible.")
        return read_zip(upload.content, limits).files
    repo, _, ref = scan.source_ref.partition("@")
    target = parse_repo(repo, ref or None)
    token = settings.github_token.get_secret_value() if settings.github_token else None
    # Latido durante la descarga: sin él, una descarga de más de 2 min haría que el reaper
    # devolviera a la cola un escaneo que este worker sigue procesando.
    scan_id = scan.id

    def tick(_received: int) -> None:
        if queue.heartbeat(scan_id):
            raise ScanCanceledByUser()

    data = download_zipball(target, max_bytes=settings.github_max_mb * 1024 * 1024, token=token, on_tick=tick)
    contents = read_zip(data, limits, strip_root=True)
    if contents.root_prefix:
        # La carpeta raíz es "<repo>-<commit>" (o "<repo>-<etiqueta>" si se pidió una etiqueta).
        sha = contents.root_prefix.rstrip("/").rsplit("-", 1)[-1]
        if 7 <= len(sha) <= 40 and all(c in "0123456789abcdef" for c in sha.lower()):
            scan.commit_sha = sha
    return contents.files


def process(scan_id: uuid.UUID, settings) -> str:
    """Procesa un escaneo ya reclamado. Devuelve el estado final."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return "missing"
    upload = db.session.get(ScanUpload, scan_id)
    ruleset = default_ruleset() if scan.rules_requested is None else default_ruleset().select(ids=scan.rules_requested)
    status, error_code = "failed", None
    audit.record("scan.start", target_type="scan", target_id=scan.id, source=scan.source)
    db.session.commit()
    try:
        files = materialize(scan, upload, settings)
        # El total real lo da el motor tras excluir pruebas y terceros; hasta entonces la
        # barra es indeterminada. También borra el progreso de un intento anterior (reaper).
        scan.progress_done, scan.progress_total = 0, 0
        db.session.commit()
        # ZIP y GitHub excluyen pruebas, dependencias y minificados igual que la CLI; el código
        # pegado es un único archivo elegido por el usuario y se analiza siempre.
        apply_excludes = scan.source != "snippet"
        key = result_cache.cache_key(result_cache.content_digest(files), scan.rules_requested, apply_excludes)
        report = result_cache.get(key, scan.source_ref)
        reused = report is not None
        if report is None:
            report = run_isolated(files, scan.rules_requested, timeout_s=settings.scan_timeout_s,
                                  on_tick=lambda d, t: queue.heartbeat(scan_id, d, t),
                                  apply_excludes=apply_excludes, release_input=True)
            result_cache.put(key, report)
        del files
        scan = db.session.get(Scan, scan_id)
        scan.result_reused, scan.partial = reused, report.partial
        scan.rules_enabled = ruleset.ids
        scan.engine_version = __version__
        scan.files_scanned, scan.loc_total = report.files_scanned, report.loc_total
        scan.progress_done = report.files_scanned
        scan.progress_total = report.files_total or report.files_scanned  # en un parcial, total > hechos
        scan.rule_errors = [e.to_dict() for e in report.rule_errors]
        finished = utcnow()
        issue_service.ingest(scan, report, ruleset, finished_at=finished)
        status = "done"
    except ScanTimeout:
        error_code = "timeout"
    except ScanCanceledByUser:
        status = "canceled"
    except (ArchiveError, GitHubError) as exc:
        error_code = exc.code
    except Exception:
        log.exception("fallo procesando el escaneo", extra={"scan_id": str(scan_id)})
        db.session.rollback()
        error_code = "internal"
    finally:
        scan = db.session.get(Scan, scan_id)
        scan.status, scan.error_code, scan.finished_at = status, error_code, utcnow()
        db.session.execute(delete(ScanUpload).where(ScanUpload.scan_id == scan_id))
        audit.record("scan.finish", target_type="scan", target_id=scan_id,
                     outcome="success" if status == "done" else status, error_code=error_code)
        db.session.commit()
    log.info("escaneo terminado", extra={"scan_id": str(scan_id), "status": status})
    return status


def purge(retention_days: int) -> int:
    """Borra ocurrencias de escaneos antiguos (conserva el resumen) y subidas huérfanas."""
    from ..models.entities import Occurrence

    limit = utcnow() - timedelta(days=retention_days)
    old = db.session.query(Scan.id).filter(Scan.finished_at < limit).subquery()
    n = db.session.execute(delete(Occurrence).where(Occurrence.scan_id.in_(db.select(old.c.id)))).rowcount or 0
    db.session.execute(delete(ScanUpload).where(ScanUpload.created_at < utcnow() - timedelta(hours=1)))
    result_cache.purge()
    db.session.commit()
    return n
