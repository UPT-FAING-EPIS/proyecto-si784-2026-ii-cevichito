"""Catálogo de reglas: /api/v1/rules."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from sast.rules.api import Severity
from sast.rules.registry import default_ruleset

from ..errors import ApiError
from ..security.session import login_required
from ..views import serializers

bp = Blueprint("rules", __name__, url_prefix="/api/v1/rules")


@bp.get("")
@login_required
def list_rules():
    metas = default_ruleset().metas()
    language = request.args.get("language")
    severity = request.args.get("severity")
    if language:
        metas = [m for m in metas if language in m.languages]
    if severity:
        try:
            sev = Severity.parse(severity)
        except KeyError:
            raise ApiError(400, "invalid_severity", "Severidad no válida.") from None
        metas = [m for m in metas if m.severity == sev]
    return jsonify([serializers.rule(m) for m in metas])


@bp.get("/<path:rule_id>")
@login_required
def get_rule(rule_id: str):
    rule = default_ruleset().get(rule_id)
    if rule is None:
        raise ApiError(404)
    return jsonify(serializers.rule(rule.meta))
