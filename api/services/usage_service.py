"""Métricas de uso del producto para el dashboard de administración (/uso).

Todo se calcula con consultas sobre las tablas que ya existen; no se guarda nada extra
del usuario. Las series se agrupan por día (UTC) en Python para funcionar igual en
PostgreSQL y en SQLite.
"""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime, timedelta, timezone
from statistics import median

from sqlalchemy import func, select

from ..challenges import catalog
from ..extensions import db
from ..models.entities import AuthSession, Issue, Occurrence, Project, Scan, User, utcnow

MAX_DAYS = 365


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _days(desde: date, hasta: date) -> list[date]:
    return [desde + timedelta(days=i) for i in range((hasta - desde).days + 1)]


def usage(days: int = 30) -> dict:
    days = max(1, min(MAX_DAYS, days))
    ahora = utcnow()
    desde = ahora - timedelta(days=days)
    dias = _days(desde.date(), ahora.date())

    scans = list(db.session.execute(
        select(Scan.queued_at, Scan.started_at, Scan.finished_at, Scan.status, Scan.source, Scan.created_by,
               Project.challenge_id)
        .join(Project, Scan.project_id == Project.id)
        .where(Scan.queued_at >= desde)))
    users_nuevos = [_utc(c) for (c,) in db.session.execute(select(User.created_at).where(User.created_at >= desde))]
    sesiones = list(db.session.execute(
        select(AuthSession.user_id, AuthSession.last_seen_at).where(AuthSession.last_seen_at >= desde)))

    # --- Series por día ---------------------------------------------------------------------
    por_dia = {d: {"date": d.isoformat(), "scans": 0, "failed": 0, "active_users": set(), "new_users": 0}
               for d in dias}
    for s in scans:
        fila = por_dia.get(_utc(s.queued_at).date())
        if fila is None:
            continue
        fila["scans"] += 1
        fila["failed"] += s.status == "failed"
        if s.created_by:
            fila["active_users"].add(s.created_by)
    for user_id, visto in sesiones:
        fila = por_dia.get(_utc(visto).date())
        if fila:
            fila["active_users"].add(user_id)
    for creado in users_nuevos:
        fila = por_dia.get(creado.date())
        if fila:
            fila["new_users"] += 1
    serie = [{**f, "active_users": len(f["active_users"])} for f in por_dia.values()]

    # --- Totales -----------------------------------------------------------------------------
    duraciones = sorted((_utc(s.finished_at) - _utc(s.started_at)).total_seconds()
                        for s in scans if s.status == "done" and s.started_at and s.finished_at)
    activos = {u for u, _ in sesiones} | {s.created_by for s in scans if s.created_by}
    estados = Counter(s.status for s in scans)
    fuentes = Counter("reto" if s.challenge_id else s.source for s in scans)

    hallazgos = db.session.scalar(
        select(func.count()).select_from(Occurrence).join(Scan, Occurrence.scan_id == Scan.id)
        .where(Scan.queued_at >= desde, Occurrence.suppressed.is_(False))) or 0
    corregidos = db.session.scalar(
        select(func.count()).select_from(Issue).where(Issue.fixed_at.is_not(None), Issue.fixed_at >= desde)) or 0

    top_reglas = db.session.execute(
        select(Issue.rule_id, func.count()).select_from(Occurrence).join(Issue, Occurrence.issue_id == Issue.id)
        .join(Scan, Occurrence.scan_id == Scan.id)
        .where(Scan.queued_at >= desde, Occurrence.suppressed.is_(False))
        .group_by(Issue.rule_id).order_by(func.count().desc(), Issue.rule_id).limit(8)).all()

    # --- Retos -------------------------------------------------------------------------------
    intentos = list(db.session.execute(
        select(Project.challenge_id, Project.challenge_solved_at).where(Project.challenge_id.is_not(None))))
    por_reto = Counter(c for c, _ in intentos)
    superados = Counter(c for c, resuelto in intentos if resuelto)
    retos = [{"id": ch.id, "title": ch.title, "attempts": por_reto[ch.id], "solved": superados[ch.id]}
             for ch in catalog().values()]

    return {
        "days": days,
        "from": desde.isoformat(),
        "to": ahora.isoformat(),
        "totals": {
            "users": db.session.scalar(select(func.count()).select_from(User)) or 0,
            "active_users": len(activos),
            "new_users": len(users_nuevos),
            "projects": db.session.scalar(select(func.count()).select_from(Project)
                                          .where(Project.challenge_id.is_(None))) or 0,
            "scans": len(scans),
            "findings": hallazgos,
            "issues_fixed": corregidos,
            "challenge_attempts": len(intentos),
            "challenges_solved": sum(superados.values()),
            "scan_seconds_median": round(median(duraciones), 2) if duraciones else None,
            "scan_seconds_p95": round(duraciones[int(0.95 * (len(duraciones) - 1))], 2) if duraciones else None,
            "failure_rate": round(estados["failed"] / len(scans), 3) if scans else None,
        },
        "by_status": dict(sorted(estados.items())),
        "by_source": dict(sorted(fuentes.items())),
        "daily": serie,
        "top_rules": [{"rule_id": r, "count": n} for r, n in top_reglas],
        "challenges": retos,
    }
