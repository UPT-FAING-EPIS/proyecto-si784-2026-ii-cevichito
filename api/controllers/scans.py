"""Escaneos: estado, cancelación, hallazgos, diff e informes (/api/v1/scans)."""

from __future__ import annotations

from flask import Blueprint, Response, g, jsonify, request
from sqlalchemy import select

from sast.rules.api import Severity

from ..errors import ApiError
from ..extensions import db
from ..models.entities import CHANGES, TRIAGES, Issue, Occurrence
from ..security.session import login_required
from ..services import access, metrics_service, report_service, scan_jobs
from ..views import serializers
from ._common import page_params, paginated

bp = Blueprint("scans", __name__, url_prefix="/api/v1/scans")


@bp.get("/<scan_id>")
@login_required
def get_scan(scan_id: str):
    return jsonify(serializers.scan(access.scan_of(g.user, scan_id)))


@bp.post("/<scan_id>/cancel")
@login_required
def cancel(scan_id: str):
    scan = access.scan_of(g.user, scan_id)
    status = scan_jobs.request_cancel(scan)
    db.session.commit()
    return jsonify({"status": status}), 202


@bp.get("/<scan_id>/findings")
@login_required
def findings(scan_id: str):
    scan = access.scan_of(g.user, scan_id)
    q = select(Occurrence).join(Issue, Occurrence.issue_id == Issue.id).where(Occurrence.scan_id == scan.id)
    args = request.args
    if args.get("severity"):
        try:
            q = q.where(Occurrence.severity == int(Severity.parse(args["severity"])))
        except KeyError:
            raise ApiError(400, "invalid_severity", "Severidad no válida.") from None
    if args.get("rule_id"):
        q = q.where(Issue.rule_id == args["rule_id"])
    if args.get("path"):
        q = q.where(Occurrence.path.startswith(args["path"]))
    if args.get("change"):
        if args["change"] not in CHANGES:
            raise ApiError(400, "invalid_change", "Cambio no válido.")
        q = q.where(Occurrence.change == args["change"])
    if args.get("triage"):
        if args["triage"] not in TRIAGES:
            raise ApiError(400, "invalid_triage", "Triage no válido.")
        q = q.where(Issue.triage == args["triage"])
    limit, offset = page_params()
    rows = list(db.session.scalars(q.order_by(Occurrence.severity.desc(), Occurrence.path, Occurrence.start_line,
                                              Occurrence.id).offset(offset).limit(limit + 1)))
    return paginated([serializers.occurrence(o) for o in rows[:limit]], limit, offset, len(rows) > limit)


@bp.get("/<scan_id>/diff")
@login_required
def diff(scan_id: str):
    scan = access.scan_of(g.user, scan_id)
    if request.args.get("base"):
        base = access.scan_of(g.user, request.args["base"])
        if (base.project_id, base.category) != (scan.project_id, scan.category):
            raise ApiError(422, "different_streams", "Solo se comparan escaneos del mismo proyecto y categoría.")
    elif scan.baseline_scan_id:
        base = access.scan_of(g.user, str(scan.baseline_scan_id))
    else:
        return jsonify({"base_scan_id": None, "new": [], "fixed": [], "reopened": [], "persisting_count": 0})
    d = metrics_service.scan_diff(scan, base)
    return jsonify({
        "base_scan_id": str(base.id),
        "new": [serializers.occurrence(o) for o in d["new"]],
        "fixed": [serializers.occurrence(o) for o in d["fixed"]],
        "reopened": [serializers.occurrence(o) for o in d["reopened"]],
        "persisting_count": d["persisting_count"],
    })


@bp.get("/<scan_id>/report")
@login_required
def report(scan_id: str):
    scan = access.scan_of(g.user, scan_id)
    if scan.status != "done":
        raise ApiError(409, "scan_not_finished", "El informe estará disponible cuando termine el escaneo.")
    fmt = request.args.get("format", "json")
    if fmt not in {"sarif", "json", "html"}:
        raise ApiError(400, "invalid_format", "Formato no válido (sarif, json o html).")
    body, mimetype, ext = report_service.render(scan, fmt)
    resp = Response(body, mimetype=mimetype)
    resp.headers["Content-Disposition"] = f'attachment; filename="sast-{scan.id}.{ext}"'
    return resp
