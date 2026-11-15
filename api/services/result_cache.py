"""Caché de resultados del motor por contenido.

Si 30 estudiantes escanean el mismo repositorio en el mismo commit, el motor solo trabaja una
vez: los otros 29 escaneos reutilizan el resultado. Cada escaneo sigue teniendo su propio
historial, porque `issue_service.ingest` se ejecuta igual para cada uno, en su proyecto.

Seguridad: la clave es un hash del contenido analizado junto con la versión del motor y las
reglas pedidas. Solo coincide quien ya tiene exactamente el mismo código, así que reutilizar
el resultado no revela nada que no tenga ya.

Se guarda JSON comprimido (nunca pickle: leer pickle de la base de datos permitiría ejecutar
código si alguien la manipulara).
"""

from __future__ import annotations

import hashlib
import json
import zlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from sast import __version__
from sast.engine.runner import ScanReport
from sast.rules.api import Confidence, Finding, RuleError, Severity, TraceStep

from ..extensions import db
from ..models.entities import ScanResultCache, utcnow

TTL = timedelta(days=7)
CACHE_FORMAT = "1"


def content_digest(files: list[tuple[str, str]]) -> str:
    """Hash estable del conjunto de archivos (ruta y contenido), independiente del orden."""
    h = hashlib.sha256()
    for path, source in sorted(files):
        h.update(path.encode("utf-8", "replace") + b"\0")
        h.update(hashlib.sha256(source.encode("utf-8", "replace")).digest())
    return h.hexdigest()


def cache_key(digest: str, rule_ids: list[str] | None, apply_excludes: bool) -> str:
    rules = ",".join(sorted(rule_ids)) if rule_ids is not None else "*"
    raw = f"v{CACHE_FORMAT}|{__version__}|{rules}|{int(apply_excludes)}|{digest}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _encode(report: ScanReport) -> bytes:
    data = {
        "findings": [f.to_dict() for f in report.findings],
        "rule_errors": [e.to_dict() for e in report.rule_errors],
        "file_errors": report.file_errors,
        "files_scanned": report.files_scanned,
        "files_total": report.files_total,
        "loc_total": report.loc_total,
        "rules_enabled": report.rules_enabled,
        "sources": report.sources,
    }
    return zlib.compress(json.dumps(data, ensure_ascii=False).encode("utf-8"), level=6)


def _decode(payload: bytes, target: str) -> ScanReport:
    data = json.loads(zlib.decompress(payload).decode("utf-8"))
    findings = [
        Finding(
            rule_id=f["rule_id"], path=f["path"], line=f["line"], col=f["col"], end_line=f["end_line"],
            end_col=f["end_col"], message=f["message"], severity=Severity.parse(f["severity"]),
            confidence=Confidence.parse(f["confidence"]),
            trace=tuple(TraceStep(t["line"], t["description"]) for t in f.get("trace") or []),
            variant=f.get("variant"), suppressed=f.get("suppressed", False),
            suppression_reason=f.get("suppression_reason"), snippet=f.get("snippet", ""),
            fingerprint=f.get("fingerprint", ""),
        )
        for f in data["findings"]
    ]
    return ScanReport(
        target=target, findings=findings, rule_errors=[RuleError(**e) for e in data["rule_errors"]],
        file_errors=data["file_errors"], files_scanned=data["files_scanned"], files_total=data["files_total"],
        loc_total=data["loc_total"], rules_enabled=data["rules_enabled"], sources=data["sources"],
    )


def _aware(dt: datetime) -> datetime:
    # SQLite devuelve las fechas sin zona; todas se guardan en UTC.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def get(key: str, target: str) -> ScanReport | None:
    row = db.session.get(ScanResultCache, key)
    if row is None or _aware(row.created_at) < utcnow() - TTL:
        return None
    try:
        report = _decode(row.payload, target)
    except (ValueError, KeyError, TypeError, zlib.error):
        return None  # formato antiguo o dañado: se vuelve a analizar
    row.hits += 1
    return report


def put(key: str, report: ScanReport) -> None:
    """Guarda solo resultados completos: uno parcial depende del tiempo, no del contenido."""
    if report.partial:
        return
    row = db.session.get(ScanResultCache, key)
    payload = _encode(report)
    if row is None:
        db.session.add(ScanResultCache(key=key, payload=payload, created_at=utcnow(), hits=0))
    else:
        row.payload, row.created_at = payload, utcnow()


def purge() -> int:
    return db.session.execute(delete(ScanResultCache).where(ScanResultCache.created_at < utcnow() - TTL)).rowcount or 0
