"""Dashboard de uso del producto: /api/v1/usage (solo administradores)."""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from ..errors import ApiError
from ..security.session import login_required
from ..services import access, usage_service

bp = Blueprint("usage", __name__, url_prefix="/api/v1")


@bp.get("/usage")
@login_required
def usage():
    access.require_admin(g.user)
    try:
        days = int(request.args.get("days", 30))
    except ValueError:
        raise ApiError(400, "invalid_days", "'days' debe ser un número de días.") from None
    return jsonify(usage_service.usage(days))
