"""Controlador de autenticación: /api/v1/auth/*."""

from __future__ import annotations

import logging

from flask import Blueprint, current_app, g, jsonify, make_response, redirect, request

from ..errors import ApiError
from ..extensions import db, limiter
from ..security import session as sess
from ..services import audit, auth_service
from ..views import serializers

bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")
log = logging.getLogger("api.auth")
AUTH_LIMIT = "10/minute"


def _settings():
    return current_app.config["SETTINGS"]


def _open_session(user, status: int = 200, redirect_to: str | None = None):
    settings = _settings()
    session, token = sess.create_session(user, settings)
    audit.record("auth.login.success", user_sub=user.google_sub, target_type="user", target_id=user.id)
    db.session.commit()
    if redirect_to:
        resp = redirect(redirect_to, code=302)
    else:
        resp = make_response(jsonify(serializers.me(user, sess.csrf_token_for(session, settings))), status)
    sess.set_cookie(resp, token, settings)
    return resp


@bp.get("/login")
@limiter.limit(AUTH_LIMIT)
def login():
    settings = _settings()
    if not settings.google_client_id or not settings.google_client_secret:
        raise ApiError(501, "oauth_disabled", "El inicio de sesión con OIDC no está configurado en este servidor.")
    try:
        url, cookie = auth_service.start_login(settings, request.args.get("next"))
    except auth_service.AuthError as exc:  # el proveedor no responde o su descubrimiento no cuadra
        log.warning("no se pudo iniciar el login: %s", exc.reason)
        raise ApiError(502, "oidc_unavailable", "El proveedor de identidad no responde. Inténtalo más tarde.") from None
    resp = redirect(url, code=302)
    resp.set_cookie(auth_service.login_cookie_name(settings), cookie, max_age=auth_service.LOGIN_COOKIE_MAX_AGE,
                    secure=settings.is_secure, httponly=True, samesite="Lax", path="/")
    return resp


@bp.get("/callback")
@limiter.limit(AUTH_LIMIT)
def callback():
    settings = _settings()
    cookie = request.cookies.get(auth_service.login_cookie_name(settings))
    try:
        login_state = auth_service.read_login_cookie(settings, cookie)
        if request.args.get("error"):
            raise auth_service.AuthError(f"provider_error:{request.args.get('error')[:40]}")
        user = auth_service.complete_login(settings, code=request.args.get("code"), state=request.args.get("state"),
                                           login=login_state)
    except auth_service.AuthError as exc:
        log.warning("login rechazado: %s", exc.reason)
        audit.record("auth.login.failure", outcome="failure", reason=exc.reason)
        db.session.commit()
        # Vuelve a la pantalla de acceso con un código genérico: el motivo real solo va al log.
        resp = redirect(settings.public_origin.rstrip("/") + "/login?error=login_failed", code=302)
        resp.delete_cookie(auth_service.login_cookie_name(settings), path="/")
        return resp
    resp = _open_session(user, redirect_to=settings.public_origin.rstrip("/") + login_state.next_path)
    resp.delete_cookie(auth_service.login_cookie_name(settings), path="/")
    return resp


@bp.post("/dev-login")
@limiter.limit(AUTH_LIMIT)
def dev_login():
    settings = _settings()
    if not settings.dev_login_enabled or settings.environment == "prod":
        raise ApiError(404)
    body = request.get_json(silent=True) or {}
    email = str(body.get("email") or "").strip().lower()
    if "@" not in email or len(email) > 320:
        raise ApiError(422, "invalid_email", "Indica un email válido.")
    name = str(body.get("name") or email.split("@")[0])[:200]
    user = auth_service.upsert_user(f"dev|{email}", email, name)
    return _open_session(user)


@bp.post("/logout")
@sess.login_required
def logout():
    settings = _settings()
    sess.revoke(g.session)
    audit.record("auth.logout", target_type="user", target_id=g.user.id)
    db.session.commit()
    resp = make_response("", 204)
    sess.clear_cookie(resp, settings)
    return resp


@bp.get("/me")
@sess.login_required
def me():
    return jsonify(serializers.me(g.user, sess.csrf_token_for(g.session, _settings())))
