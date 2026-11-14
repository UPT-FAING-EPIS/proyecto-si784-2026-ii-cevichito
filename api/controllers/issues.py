"""Issues: detalle, triage, historial y comentarios (/api/v1/issues)."""

from __future__ import annotations

from flask import Blueprint, g, jsonify
from sqlalchemy import select

from sast.rules.registry import default_ruleset

from ..errors import ApiError
from ..extensions import db
from ..models.entities import TRIAGES, IssueEvent, Occurrence, Scan, User
from ..security.session import login_required
from ..services import access, audit, issue_service
from ..views import serializers
from ._common import json_body

bp = Blueprint("issues", __name__, url_prefix="/api/v1/issues")
MAX_TEXT = 2000


def _detail(issue):
    last = db.session.scalars(select(Occurrence).join(Scan, Occurrence.scan_id == Scan.id)
                              .where(Occurrence.issue_id == issue.id).order_by(Scan.queued_at.desc()).limit(1)).first()
    rule = default_ruleset().get(issue.rule_id)
    return serializers.issue(issue, last, rule.meta if rule else None)


@bp.get("/<issue_id>")
@login_required
def get_issue(issue_id: str):
    return jsonify(_detail(access.issue_of(g.user, issue_id)))


@bp.patch("/<issue_id>")
@login_required
def triage(issue_id: str):
    issue = access.issue_of(g.user, issue_id)
    body = json_body()
    value = body.get("triage")
    justification = body.get("justification")
    if value not in TRIAGES:
        raise ApiError(400, "invalid_triage", f"'triage' debe ser uno de: {', '.join(TRIAGES)}.")
    if justification is not None and (not isinstance(justification, str) or len(justification) > MAX_TEXT):
        raise ApiError(400, "invalid_justification", f"La justificación debe tener como máximo {MAX_TEXT} caracteres.")
    try:
        issue_service.set_triage(issue, value, justification, g.user.id)
    except ValueError:
        raise ApiError(422, "justification_required", "Este estado requiere una justificación.") from None
    audit.record("issue.triage", target_type="issue", target_id=issue.id, triage=value)
    db.session.commit()
    return jsonify(_detail(issue))


@bp.get("/<issue_id>/events")
@login_required
def events(issue_id: str):
    issue = access.issue_of(g.user, issue_id)
    rows = list(db.session.scalars(select(IssueEvent).where(IssueEvent.issue_id == issue.id)
                                   .order_by(IssueEvent.created_at, IssueEvent.id)))
    user_ids = {e.user_id for e in rows if e.user_id}
    users = {u.id: u for u in db.session.scalars(select(User).where(User.id.in_(user_ids)))} if user_ids else {}
    return jsonify([serializers.event(e, users) for e in rows])


@bp.post("/<issue_id>/comments")
@login_required
def comment(issue_id: str):
    issue = access.issue_of(g.user, issue_id)
    text = json_body().get("body")
    if not isinstance(text, str) or not (1 <= len(text.strip()) <= MAX_TEXT):
        raise ApiError(400, "invalid_comment", f"El comentario debe tener entre 1 y {MAX_TEXT} caracteres.")
    issue_service.add_comment(issue, text.strip(), g.user.id)
    db.session.commit()
    return jsonify({"ok": True}), 201
