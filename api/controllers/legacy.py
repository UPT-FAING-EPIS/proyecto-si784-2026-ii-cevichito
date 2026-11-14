"""Alias temporales: /api/<ruta> responde 308 hacia /api/v1/<ruta> durante una versión."""

from __future__ import annotations

from flask import Blueprint, redirect, request

from ..errors import ApiError

bp = Blueprint("legacy", __name__)


@bp.route("/api/<path:rest>", methods=["GET", "POST", "PATCH", "DELETE"])
def alias(rest: str):
    if rest.startswith("v1/") or rest == "v1":
        raise ApiError(404)
    target = f"/api/v1/{rest}"
    if request.query_string:
        target += "?" + request.query_string.decode("latin-1")
    return redirect(target, code=308)
