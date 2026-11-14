"""Sesión en el servidor (patrón BFF, RNF-01).

El navegador solo guarda un ID opaco de 256 bits en una cookie `HttpOnly`,
`Secure`, `SameSite=Strict` y sin `Domain`. En la base de datos se guarda su
SHA-256. La sesión caduca por inactividad y por tiempo absoluto, y el logout
la revoca. Nunca hay tokens en la URL ni en `localStorage`.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, current_app, g, request
from sqlalchemy import select

from ..errors import ApiError
from ..extensions import db
from ..models.entities import AuthSession, User, utcnow

TOUCH_EVERY = timedelta(seconds=60)


def cookie_name(settings) -> str:
    # El prefijo __Host- exige Secure; en desarrollo con http://localhost se usa un nombre sin prefijo.
    return "__Host-sast_session" if settings.is_secure else "sast_session"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def csrf_token_for(session: AuthSession, settings) -> str:
    key = settings.session_hmac_key.get_secret_value().encode("utf-8")
    return hmac.new(key, f"{session.id}:{session.csrf_secret}".encode(), hashlib.sha256).hexdigest()


def create_session(user: User, settings) -> tuple[AuthSession, str]:
    token = secrets.token_urlsafe(32)
    now = utcnow()
    session = AuthSession(user_id=user.id, token_hash=_hash(token), csrf_secret=secrets.token_hex(32),
                          created_at=now, last_seen_at=now,
                          expires_at=now + timedelta(hours=settings.session_absolute_hours),
                          ip=request.remote_addr, user_agent=(request.user_agent.string or "")[:400])
    db.session.add(session)
    db.session.flush()
    return session, token


def set_cookie(response, token: str, settings) -> None:
    response.set_cookie(cookie_name(settings), token, max_age=settings.session_absolute_hours * 3600,
                        secure=settings.is_secure, httponly=True, samesite="Strict", path="/")


def clear_cookie(response, settings) -> None:
    response.delete_cookie(cookie_name(settings), path="/", secure=settings.is_secure, httponly=True, samesite="Strict")


def revoke(session: AuthSession) -> None:
    session.revoked_at = utcnow()


def load_session() -> None:
    settings = current_app.config["SETTINGS"]
    g.user = None
    g.session = None
    token = request.cookies.get(cookie_name(settings))
    if not token or len(token) > 200:
        return
    session = db.session.scalar(select(AuthSession).where(AuthSession.token_hash == _hash(token)))
    if session is None or session.revoked_at is not None:
        return
    now = utcnow()
    idle = timedelta(minutes=settings.session_idle_minutes)
    if now >= _aware(session.expires_at) or now - _aware(session.last_seen_at) > idle:
        return
    user = db.session.get(User, session.user_id)
    if user is None or user.disabled_at is not None:
        return
    if now - _aware(session.last_seen_at) > TOUCH_EVERY:
        session.last_seen_at = now
        db.session.commit()
    g.user, g.session = user, session


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if getattr(g, "user", None) is None:
            raise ApiError(401)
        return view(*args, **kwargs)

    return wrapper


def init_session(app: Flask) -> None:
    app.before_request(load_session)
