"""Proyectos y sus escaneos, issues y métricas: /api/v1/projects."""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from sast.rules.api import Severity

from ..errors import ApiError
from ..extensions import db
from ..models.entities import LIFECYCLES, TRIAGES, Issue, Project, Scan
from ..security.session import login_required
from ..services import access, audit, metrics_service, scan_jobs
from ..views import serializers
from ._common import json_body, page_params, paginated, parse_date, settings

bp = Blueprint("projects", __name__, url_prefix="/api/v1/projects")
MAX_NAME = 120


def _name(body: dict) -> str:
    name = body.get("name")
    if not isinstance(name, str) or not (1 <= len(name.strip()) <= MAX_NAME):
        raise ApiError(400, "invalid_name", f"El nombre debe tener entre 1 y {MAX_NAME} caracteres.")
    return name.strip()


def _last_scan(project_id) -> Scan | None:
    return db.session.scalars(select(Scan).where(Scan.project_id == project_id)
                              .order_by(Scan.queued_at.desc()).limit(1)).first()


def _open_counts(project_id) -> dict[str, int]:
    rows = db.session.execute(
        select(Issue.severity, func.count()).where(Issue.project_id == project_id, Issue.lifecycle != "fixed",
                                                   Issue.triage != "false_positive").group_by(Issue.severity))
    counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
    for sev, n in rows:
        counts[Severity(sev).label] = n
    return counts


@bp.get("")
@login_required
def list_projects():
    limit, offset = page_params()
    rows = list(db.session.scalars(select(Project).where(Project.owner_id == g.user.id)
                                   .order_by(Project.created_at.desc(), Project.id).offset(offset).limit(limit + 1)))
    items = [serializers.project(p, _last_scan(p.id), _open_counts(p.id)) for p in rows[:limit]]
    return paginated(items, limit, offset, len(rows) > limit)


@bp.post("")
@login_required
def create_project():
    project = Project(owner_id=g.user.id, name=_name(json_body()))
    db.session.add(project)
    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        raise ApiError(409, "duplicate_name", "Ya tienes un proyecto con ese nombre.") from None
    audit.record("project.create", target_type="project", target_id=project.id)
    db.session.commit()
    return jsonify(serializers.project(project, None, _open_counts(project.id))), 201


@bp.get("/<project_id>")
@login_required
def get_project(project_id: str):
    p = access.project_of(g.user, project_id)
    return jsonify(serializers.project(p, _last_scan(p.id), _open_counts(p.id)))


@bp.patch("/<project_id>")
@login_required
def rename_project(project_id: str):
    p = access.project_of(g.user, project_id)
    p.name = _name(json_body())
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise ApiError(409, "duplicate_name", "Ya tienes un proyecto con ese nombre.") from None
    return jsonify(serializers.project(p, _last_scan(p.id), _open_counts(p.id)))


@bp.delete("/<project_id>")
@login_required
def delete_project(project_id: str):
    p = access.project_of(g.user, project_id)
    audit.record("data.delete", target_type="project", target_id=p.id)
    db.session.delete(p)
    db.session.commit()
    return "", 204


# --- Escaneos del proyecto -------------------------------------------------------------

@bp.post("/<project_id>/scans")
@login_required
def create_scan(project_id: str):
    p = access.project_of(g.user, project_id)
    cfg = settings()
    if request.mimetype == "multipart/form-data":
        upload = request.files.get("file")
        if upload is None:
            raise ApiError(422, "missing_file", "Falta el archivo 'file'.")
        data = upload.read(cfg.max_upload_mb * 1024 * 1024 + 1)
        rules = request.form.getlist("rules") or None
        scan = scan_jobs.create_scan(g.user, p, source="zip", zip_bytes=data, filename=upload.filename,
                                     rules=rules, category=request.form.get("category"), settings=cfg,
                                     request_id=g.request_id)
        audit.record("upload.received", target_type="scan", target_id=scan.id, size=len(data))
    elif request.is_json:
        body = json_body()
        source = body.get("source")
        if source == "snippet":
            scan = scan_jobs.create_scan(g.user, p, source="snippet", filename=body.get("filename"),
                                         code=body.get("code"), rules=body.get("rules"), category=body.get("category"),
                                         settings=cfg, request_id=g.request_id)
        elif source == "github":
            scan = scan_jobs.create_scan(g.user, p, source="github", repo=body.get("repo"), ref=body.get("ref"),
                                         rules=body.get("rules"), category=body.get("category"), settings=cfg,
                                         request_id=g.request_id)
        else:
            raise ApiError(422, "invalid_source", "'source' debe ser 'snippet' o 'github' (o enviar un ZIP).")
    else:
        raise ApiError(415, "unsupported_media_type", "Envía JSON o multipart/form-data.")
    db.session.commit()
    resp = jsonify({"id": str(scan.id), "status": scan.status})
    resp.status_code = 202
    resp.headers["Location"] = f"/api/v1/scans/{scan.id}"
    return resp


@bp.get("/<project_id>/scans")
@login_required
def list_scans(project_id: str):
    p = access.project_of(g.user, project_id)
    limit, offset = page_params()
    rows = list(db.session.scalars(select(Scan).where(Scan.project_id == p.id)
                                   .order_by(Scan.queued_at.desc(), Scan.id).offset(offset).limit(limit + 1)))
    return paginated([serializers.scan(s) for s in rows[:limit]], limit, offset, len(rows) > limit)


# --- Issues y métricas ------------------------------------------------------------------

@bp.get("/<project_id>/issues")
@login_required
def list_issues(project_id: str):
    p = access.project_of(g.user, project_id)
    q = select(Issue).where(Issue.project_id == p.id)
    lifecycle, triage = request.args.get("lifecycle"), request.args.get("triage")
    if lifecycle:
        if lifecycle not in LIFECYCLES:
            raise ApiError(400, "invalid_lifecycle", "Estado no válido.")
        q = q.where(Issue.lifecycle == lifecycle)
    if triage:
        if triage not in TRIAGES:
            raise ApiError(400, "invalid_triage", "Triage no válido.")
        q = q.where(Issue.triage == triage)
    if request.args.get("severity"):
        try:
            q = q.where(Issue.severity == int(Severity.parse(request.args["severity"])))
        except KeyError:
            raise ApiError(400, "invalid_severity", "Severidad no válida.") from None
    if request.args.get("rule_id"):
        q = q.where(Issue.rule_id == request.args["rule_id"])
    if request.args.get("path"):
        q = q.where(Issue.current_path.startswith(request.args["path"]))
    limit, offset = page_params()
    rows = list(db.session.scalars(q.order_by(Issue.severity.desc(), Issue.current_path, Issue.current_line, Issue.id)
                                   .offset(offset).limit(limit + 1)))
    return paginated([serializers.issue(i) for i in rows[:limit]], limit, offset, len(rows) > limit)


@bp.get("/<project_id>/metrics")
@login_required
def metrics(project_id: str):
    p = access.project_of(g.user, project_id)
    return jsonify(metrics_service.project_metrics(p.id, parse_date("from"), parse_date("to")))
