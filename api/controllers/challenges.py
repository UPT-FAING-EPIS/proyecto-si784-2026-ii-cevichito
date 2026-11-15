"""Retos de corrección: /api/v1/challenges."""

from __future__ import annotations

from flask import Blueprint, g, jsonify

from sast.rules.registry import default_ruleset

from .. import challenges
from ..errors import ApiError
from ..extensions import db
from ..security.session import login_required
from ..services import audit, challenge_service
from ..views import serializers
from ._common import json_body, settings

bp = Blueprint("challenges", __name__, url_prefix="/api/v1/challenges")


def _challenge(challenge_id: str) -> challenges.Challenge:
    ch = challenges.get(challenge_id)
    if ch is None:
        raise ApiError(404)
    return ch


def _summary(ch: challenges.Challenge, state: str) -> dict:
    return {"id": ch.id, "order": ch.order, "title": ch.title, "level": ch.level, "cwe": ch.cwe,
            "rules": list(ch.rules), "summary": ch.summary, "state": state}


def _verdict(ch: challenges.Challenge) -> dict:
    v = challenge_service.verdict(challenge_service.attempt_of(g.user, ch), ch)
    return {
        "state": v["state"], "scan_id": str(v["scan_id"]) if v["scan_id"] else None,
        "submissions": v["submissions"], "solved_at": serializers.iso_utc(v["solved_at"]),
        "remaining": [serializers.occurrence(o) for o in v["remaining"]],
        "silenced": [serializers.occurrence(o) for o in v["silenced"]],
        "new": [serializers.occurrence(o) for o in v["new"]],
    }


@bp.get("")
@login_required
def list_challenges():
    attempts = challenge_service.attempts_by_challenge(g.user)
    return jsonify([_summary(ch, challenge_service.progress_state(attempts.get(ch.id)))
                    for ch in challenges.catalog().values()])


@bp.get("/<challenge_id>")
@login_required
def get_challenge(challenge_id: str):
    ch = _challenge(challenge_id)
    ruleset = default_ruleset()
    rules = [serializers.rule(r.meta) for rid in ch.rules if (r := ruleset.get(rid)) is not None]
    out = _summary(ch, challenge_service.progress_state(challenge_service.attempt_of(g.user, ch)))
    out.update(statement=ch.statement, hints=list(ch.hints), filename=ch.filename, starter=ch.starter,
               keep=list(ch.keep), rule_details=rules, attempt=_verdict(ch))
    return jsonify(out)


@bp.get("/<challenge_id>/attempt")
@login_required
def get_attempt(challenge_id: str):
    return jsonify(_verdict(_challenge(challenge_id)))


@bp.post("/<challenge_id>/submissions")
@login_required
def submit(challenge_id: str):
    ch = _challenge(challenge_id)
    scan = challenge_service.submit(g.user, ch, json_body().get("code"), settings(), request_id=g.request_id)
    audit.record("challenge.submit", target_type="scan", target_id=scan.id, challenge=ch.id)
    db.session.commit()
    resp = jsonify({"scan_id": str(scan.id), "status": scan.status})
    resp.status_code = 202
    return resp
