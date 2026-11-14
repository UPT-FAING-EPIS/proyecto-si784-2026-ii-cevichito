"""Creación, cuotas y cancelación de escaneos (la ejecución la hace el worker)."""

from __future__ import annotations

import hashlib
import io
import posixpath
import zipfile
from datetime import timedelta

from sqlalchemy import func, select

from sast.engine.languages import detect_language
from sast.rules.registry import default_ruleset

from ..errors import ApiError
from ..extensions import db
from ..models.entities import Project, Scan, ScanUpload, User, utcnow
from .github_fetch import GitHubError, parse_repo

ACTIVE = ("queued", "running")


def _check_quota(user: User, settings) -> None:
    active = db.session.scalar(
        select(func.count()).select_from(Scan).where(Scan.created_by == user.id, Scan.status.in_(ACTIVE)))
    if active >= settings.max_running_scans_per_user:
        raise ApiError(429, "too_many_running_scans",
                       f"Ya tienes {active} escaneos en curso. Espera a que terminen.")
    recent = db.session.scalar(
        select(func.count()).select_from(Scan).where(Scan.created_by == user.id,
                                                      Scan.queued_at >= utcnow() - timedelta(hours=1)))
    if recent >= settings.scans_per_hour:
        raise ApiError(429, "scan_quota", f"Límite de {settings.scans_per_hour} escaneos por hora alcanzado.")


def _validate_rules(rules: list[str] | None) -> list[str] | None:
    if rules is None:
        return None
    if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
        raise ApiError(422, "invalid_rules", "'rules' debe ser una lista de IDs.")
    known = set(default_ruleset().ids)
    unknown = sorted(set(rules) - known)
    if unknown:
        raise ApiError(422, "unknown_rules", "Hay reglas desconocidas.", rules=unknown)
    return rules


def _category(value: object) -> str:
    text = str(value or "default").strip()[:80]
    return text or "default"


def create_scan(user: User, project: Project, *, source: str, settings, filename: str | None = None,
                code: str | None = None, zip_bytes: bytes | None = None, repo: str | None = None,
                ref: str | None = None, rules: list[str] | None = None, category: object = None,
                request_id: str | None = None) -> Scan:
    rules = _validate_rules(rules)
    upload: ScanUpload | None = None
    scan = Scan(project_id=project.id, created_by=user.id, source=source, category=_category(category),
                status="queued", rules_requested=rules, request_id=request_id)

    if source == "snippet":
        name = posixpath.basename((filename or "snippet.py").replace("\\", "/")) or "snippet.py"
        if not detect_language(name):
            raise ApiError(422, "unsupported_language", "La extensión del archivo no corresponde a un lenguaje soportado.")
        if not isinstance(code, str) or not code.strip():
            raise ApiError(422, "empty_code", "No hay código para analizar.")
        data = code.encode("utf-8")
        if len(data) > settings.max_snippet_kb * 1024:
            raise ApiError(413, "snippet_too_large", f"El código supera {settings.max_snippet_kb} KB.")
        scan.source_ref = name
        upload = ScanUpload(filename=name, content=data)
    elif source == "zip":
        if not zip_bytes:
            raise ApiError(422, "empty_file", "No se recibió ningún archivo.")
        if len(zip_bytes) > settings.max_upload_mb * 1024 * 1024:
            raise ApiError(413, "upload_too_large", f"El archivo supera {settings.max_upload_mb} MB.")
        if not zipfile.is_zipfile(io.BytesIO(zip_bytes)):
            raise ApiError(415, "not_a_zip", "El archivo no es un ZIP válido: puede estar dañado o ser de otro formato aunque termine en .zip. Vuelve a comprimirlo.")
        scan.source_ref = posixpath.basename((filename or "upload.zip").replace("\\", "/"))[:255]
        upload = ScanUpload(filename=scan.source_ref, content=zip_bytes)
    elif source == "github":
        try:
            target = parse_repo(repo or "", ref)
        except GitHubError as exc:
            raise ApiError(422, exc.code, exc.message) from None
        scan.source_ref = target.display
        if scan.category == "default":
            scan.category = target.ref or "default"
    else:
        raise ApiError(422, "invalid_source", "Origen de escaneo no válido.")

    _check_quota(user, settings)
    db.session.add(scan)
    db.session.flush()
    if upload is not None:
        upload.scan_id = scan.id
        upload.sha256 = hashlib.sha256(upload.content).hexdigest()
        upload.size = len(upload.content)
        db.session.add(upload)
    return scan


def request_cancel(scan: Scan) -> str:
    if scan.finished:
        raise ApiError(409, "scan_finished", "El escaneo ya terminó.")
    if scan.status == "queued":
        scan.status = "canceled"
        scan.finished_at = utcnow()
        upload = db.session.get(ScanUpload, scan.id)
        if upload is not None:
            db.session.delete(upload)
        return "canceled"
    scan.cancel_requested = True
    return "canceling"
