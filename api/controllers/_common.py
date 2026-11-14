"""Utilidades comunes de los controladores: paginación, cuerpo JSON y parámetros."""

from __future__ import annotations

import base64
from datetime import datetime

from flask import current_app, jsonify, request

from ..errors import ApiError

MAX_LIMIT = 200


def settings():
    return current_app.config["SETTINGS"]


def json_body() -> dict:
    if not request.is_json:
        raise ApiError(415, "json_required", "Se esperaba un cuerpo JSON.")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ApiError(400, "invalid_json", "El cuerpo JSON no es válido.")
    return body


def page_params() -> tuple[int, int]:
    try:
        limit = min(MAX_LIMIT, max(1, int(request.args.get("limit", 50))))
    except ValueError:
        raise ApiError(400, "invalid_limit", "'limit' debe ser un número.") from None
    cursor = request.args.get("cursor")
    offset = 0
    if cursor:
        try:
            offset = int(base64.urlsafe_b64decode(cursor.encode()).decode())
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "invalid_cursor", "Cursor de paginación no válido.") from None
    return limit, max(0, offset)


def paginated(items: list, limit: int, offset: int, has_more: bool):
    nxt = base64.urlsafe_b64encode(str(offset + limit).encode()).decode() if has_more else None
    return jsonify({"items": items, "next_cursor": nxt})


def parse_date(name: str) -> datetime | None:
    raw = request.args.get(name)
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise ApiError(400, "invalid_date", f"'{name}' debe ser una fecha ISO-8601.") from None
