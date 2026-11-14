"""Protección CSRF para métodos no seguros (RNF-01).

Se exige, en este orden:
  (a) `Sec-Fetch-Site` distinto de `cross-site` (si el navegador lo envía);
  (b) `Origin` exacto dentro de la lista blanca (se rechaza `null` o ausente);
  (c) con sesión: cabecera `X-CSRF-Token` = HMAC-SHA256 ligado a la sesión,
      comparado en tiempo constante.
"""

from __future__ import annotations

import hmac

from flask import Flask, current_app, g, request

from ..errors import ApiError
from ..services import audit
from .session import csrf_token_for

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _deny(reason: str):
    audit.record("authz.denied", outcome="denied", reason=reason, path=request.path, method=request.method)
    from ..extensions import db

    db.session.commit()
    raise ApiError(403, "csrf_failed", "La petición no pasó la verificación de origen.")


def check_request() -> None:
    if request.method in SAFE_METHODS or not request.path.startswith("/api/"):
        return
    settings = current_app.config["SETTINGS"]
    if request.headers.get("Sec-Fetch-Site", "").lower() == "cross-site":
        _deny("sec-fetch-site")
    origin = (request.headers.get("Origin") or "").rstrip("/")
    if not origin or origin == "null" or origin not in settings.allowed_origins:
        _deny("origin")
    session = getattr(g, "session", None)
    if session is not None:
        sent = request.headers.get("X-CSRF-Token", "")
        if not sent or not hmac.compare_digest(sent, csrf_token_for(session, settings)):
            _deny("csrf-token")


def init_csrf(app: Flask) -> None:
    app.before_request(check_request)
