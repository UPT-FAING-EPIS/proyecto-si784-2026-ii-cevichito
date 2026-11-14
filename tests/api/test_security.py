"""F5: sesión BFF, OIDC (PKCE/state/nonce), CSRF, cabeceras, límites, errores y auditoría."""

from __future__ import annotations

import time
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import select

from api.extensions import db
from api.factory import create_app
from api.models.entities import AuditLog, AuthSession, User, utcnow
from api.services import auth_service

from .conftest import ORIGIN, ApiClient, login, make_settings

GOOGLE = dict(google_client_id="cliente-123.apps.googleusercontent.com", google_client_secret="secreto-de-prueba")


@pytest.fixture
def oidc_app(app):
    app.config["SETTINGS"] = make_settings(**GOOGLE)
    return app


@pytest.fixture
def google(monkeypatch):
    """Simula Google: firma id_tokens con una clave RSA propia y publica su JWKS."""
    key = RSAKey.generate_key(2048, private=True, parameters={"kid": "k1"})
    state = {"claims": {}}
    monkeypatch.setattr(auth_service, "fetch_jwks", lambda *a, **k: {"keys": [key.as_dict(private=False)]})

    def exchange(settings, code, verifier):
        assert code == "codigo-ok" and len(verifier) >= 43
        claims = {"iss": "https://accounts.google.com", "aud": GOOGLE["google_client_id"], "sub": "1234567890",
                  "email": "ana@example.com", "email_verified": True, "name": "Ana",
                  "iat": int(time.time()), "exp": int(time.time()) + 600, **state["claims"]}
        return {"id_token": jwt.encode({"alg": "RS256", "kid": "k1"}, claims, key)}

    monkeypatch.setattr(auth_service, "exchange_code", exchange)
    return state


def _start_login(client, next_path="/proyectos"):
    r = client.get(f"/api/v1/auth/login?next={next_path}", base_url=ORIGIN)
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["Location"]).query)
    return r, q


# --- Sesión -----------------------------------------------------------------------------

def test_dev_login_sets_secure_session_cookie(client):
    r = ApiClient(client).post("/api/v1/auth/dev-login", json={"email": "ana@example.com"})
    assert r.status_code == 200
    cookie = r.headers["Set-Cookie"]
    assert cookie.startswith("__Host-sast_session=")
    for attr in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/"):
        assert attr in cookie
    assert "Domain" not in cookie
    body = r.get_json()
    assert set(body) == {"id", "email", "name", "csrf_token"}
    token = cookie.split(";")[0].split("=", 1)[1]
    stored = db.session.scalar(select(AuthSession))
    assert stored.token_hash != token and len(stored.token_hash) == 64  # se guarda el hash, no el token


def test_me_requires_session(client):
    r = client.get("/api/v1/auth/me", base_url=ORIGIN)
    assert r.status_code == 401 and r.get_json()["error"]["code"] == "unauthenticated"


def test_logout_revokes_session(app):
    api = login(app.test_client())
    assert api.get("/api/v1/auth/me").status_code == 200
    assert api.post("/api/v1/auth/logout").status_code == 204
    assert api.get("/api/v1/auth/me").status_code == 401
    assert db.session.scalar(select(AuthSession)).revoked_at is not None


@pytest.mark.parametrize("field, delta", [("last_seen_at", timedelta(hours=3)), ("expires_at", -timedelta(hours=13))])
def test_session_expires(app, field, delta):
    api = login(app.test_client())
    s = db.session.scalar(select(AuthSession))
    if field == "last_seen_at":
        s.last_seen_at = utcnow() - delta
    else:
        s.expires_at = utcnow() + delta
    db.session.commit()
    assert api.get("/api/v1/auth/me").status_code == 401


def test_dev_login_disabled(app):
    app.config["SETTINGS"] = make_settings(dev_login_enabled=False)
    r = ApiClient(app.test_client()).post("/api/v1/auth/dev-login", json={"email": "a@b.c"})
    assert r.status_code == 404


# --- OIDC con Google ------------------------------------------------------------------------

def test_login_redirect_uses_pkce_state_and_nonce(oidc_app):
    r, q = _start_login(oidc_app.test_client())
    assert r.headers["Location"].startswith("https://accounts.google.com/")
    assert q["code_challenge_method"] == ["S256"] and len(q["code_challenge"][0]) == 43
    assert len(q["state"][0]) >= 32 and len(q["nonce"][0]) >= 32
    assert q["redirect_uri"] == [f"{ORIGIN}/api/v1/auth/callback"]
    login_cookie = r.headers["Set-Cookie"]
    assert login_cookie.startswith("__Host-sast_login=") and "SameSite=Lax" in login_cookie and "HttpOnly" in login_cookie


def test_login_disabled_without_google_config(client):
    r = client.get("/api/v1/auth/login", base_url=ORIGIN)
    assert r.status_code == 501


def test_callback_success_creates_session_without_token_in_url(oidc_app, google):
    c = oidc_app.test_client()
    _, q = _start_login(c, "/proyectos/1")
    r = c.get(f"/api/v1/auth/callback?code=codigo-ok&state={q['state'][0]}", base_url=ORIGIN)
    assert r.status_code == 302
    assert r.headers["Location"] == f"{ORIGIN}/proyectos/1"
    assert "token" not in r.headers["Location"] and "code" not in r.headers["Location"]
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert any(h.startswith("__Host-sast_session=") for h in r.headers.getlist("Set-Cookie"))
    assert c.get("/api/v1/auth/me", base_url=ORIGIN).get_json()["email"] == "ana@example.com"
    assert db.session.scalar(select(AuditLog).where(AuditLog.event == "auth.login.success")) is not None


def test_user_is_identified_by_sub_not_email(oidc_app, google):
    for email in ("ana@example.com", "ana.nueva@example.com"):
        google["claims"] = {"email": email}
        c = oidc_app.test_client()
        _, q = _start_login(c)
        assert c.get(f"/api/v1/auth/callback?code=codigo-ok&state={q['state'][0]}", base_url=ORIGIN).status_code == 302
    users = list(db.session.scalars(select(User)))
    assert len(users) == 1 and users[0].email == "ana.nueva@example.com"


@pytest.mark.parametrize("case", ["no_cookie", "state", "nonce", "aud", "unverified", "expired", "error"])
def test_callback_fails_closed(oidc_app, google, case):
    c = oidc_app.test_client()
    _, q = _start_login(c)
    state = q["state"][0]
    url = f"/api/v1/auth/callback?code=codigo-ok&state={state}"
    if case == "no_cookie":
        c = oidc_app.test_client()
    elif case == "state":
        url = "/api/v1/auth/callback?code=codigo-ok&state=otro"
    elif case == "nonce":
        google["claims"] = {"nonce": "no-coincide"}
    elif case == "aud":
        google["claims"] = {"aud": "otra-app"}
    elif case == "unverified":
        google["claims"] = {"email_verified": False}
    elif case == "expired":
        google["claims"] = {"exp": int(time.time()) - 3600}
    elif case == "error":
        url = "/api/v1/auth/callback?error=access_denied&state=" + state
    if case not in {"nonce"}:
        google["claims"].setdefault("nonce", None)
    r = c.get(url, base_url=ORIGIN)
    assert r.status_code == 302
    assert r.headers["Location"] == f"{ORIGIN}/login?error=login_failed"  # sin el motivo real en la URL
    assert c.get("/api/v1/auth/me", base_url=ORIGIN).status_code == 401
    assert db.session.scalar(select(AuditLog).where(AuditLog.event == "auth.login.failure")) is not None


@pytest.fixture(autouse=True)
def _nonce_passthrough(monkeypatch, request):
    """Por defecto el id_token simulado lleva el nonce correcto de la cookie de login."""
    if "google" not in request.fixturenames:
        return
    original = auth_service.complete_login

    def complete(settings, *, code, state, login):
        google = request.getfixturevalue("google")
        if google["claims"].get("nonce", "") is None:
            google["claims"].pop("nonce")
        google["claims"].setdefault("nonce", login.nonce)
        return original(settings, code=code, state=state, login=login)

    monkeypatch.setattr(auth_service, "complete_login", complete)


@pytest.mark.parametrize("raw", ["//evil.example/x", "https://evil.example", "/\\evil", "javascript:alert(1)", None])
def test_next_only_allows_internal_paths(raw):
    assert auth_service.safe_next(raw) == "/"


# --- OIDC con otro proveedor (OIDC_ISSUER) -----------------------------------------------------

ISSUER = "https://login.universidad.test/realms/alumnos"


class _Resp:
    def __init__(self, body, status=200):
        self._body, self.status_code = body, status

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise auth_service.requests.HTTPError(str(self.status_code))


@pytest.fixture
def generic(monkeypatch, app):
    """Proveedor OIDC genérico: descubrimiento, JWKS y token endpoint simulados en `requests`."""
    key = RSAKey.generate_key(2048, private=True, parameters={"kid": "u1"})
    state = {"claims": {}, "issuer": ISSUER, "nonce": None}
    auth_service._DISCOVERY_CACHE.clear()
    auth_service._JWKS_CACHE.clear()

    def fake_get(url, timeout=None):
        if url == f"{ISSUER}/.well-known/openid-configuration":
            return _Resp({"issuer": state["issuer"], "authorization_endpoint": f"{ISSUER}/auth",
                          "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/certs"})
        if url == f"{ISSUER}/certs":
            return _Resp({"keys": [key.as_dict(private=False)]})
        return _Resp({}, 404)

    def fake_post(url, data=None, headers=None, timeout=None):
        assert url == f"{ISSUER}/token" and data["code_verifier"]
        claims = {"iss": ISSUER, "aud": "sast-app", "sub": "u-42", "email": "ana@universidad.test", "name": "Ana",
                  "nonce": state["nonce"], "iat": int(time.time()), "exp": int(time.time()) + 600, **state["claims"]}
        return _Resp({"id_token": jwt.encode({"alg": "RS256", "kid": "u1"}, claims, key)})

    monkeypatch.setattr(auth_service.requests, "get", fake_get)
    monkeypatch.setattr(auth_service.requests, "post", fake_post)
    app.config["SETTINGS"] = make_settings(oidc_issuer=ISSUER, oidc_client_id="sast-app",
                                           oidc_client_secret="secreto-de-prueba")
    return state


def _generic_login(app, state):
    c = app.test_client()
    r, q = _start_login(c)
    state["nonce"] = q["nonce"][0]
    return r, c.get(f"/api/v1/auth/callback?code=c&state={q['state'][0]}", base_url=ORIGIN), c


def test_generic_oidc_uses_discovered_endpoints_and_prefixes_sub(app, generic):
    r, cb, c = _generic_login(app, generic)
    assert r.headers["Location"].startswith(f"{ISSUER}/auth?") and "hd=" not in r.headers["Location"]
    assert cb.status_code == 302 and cb.headers["Location"] == f"{ORIGIN}/proyectos"
    assert c.get("/api/v1/auth/me", base_url=ORIGIN).get_json()["email"] == "ana@universidad.test"
    assert db.session.scalar(select(User)).google_sub == f"{ISSUER}|u-42"  # el sub solo es único por emisor


def test_generic_oidc_accepts_missing_email_verified_but_not_false(app, generic):
    assert _generic_login(app, generic)[1].headers["Location"] == f"{ORIGIN}/proyectos"  # p. ej. Microsoft Entra
    generic["claims"] = {"email_verified": False}
    assert _generic_login(app, generic)[1].headers["Location"].endswith("/login?error=login_failed")


def test_generic_oidc_rejects_token_from_other_issuer(app, generic):
    generic["claims"] = {"iss": "https://otro.example"}
    assert _generic_login(app, generic)[1].headers["Location"].endswith("/login?error=login_failed")


def test_generic_oidc_discovery_issuer_must_match(app, generic):
    generic["issuer"] = "https://suplantador.example"
    r = app.test_client().get("/api/v1/auth/login", base_url=ORIGIN)
    assert r.status_code == 502 and r.get_json()["error"]["code"] == "oidc_unavailable"


def test_config_reports_provider_name(app, generic):
    auth = app.test_client().get("/api/v1/config", base_url=ORIGIN).get_json()["auth"]
    assert auth["oidc"] is True and auth["provider"] == "tu cuenta institucional"


# --- CSRF y origen -------------------------------------------------------------------------

def test_csrf_token_required_for_unsafe_methods(app):
    api = login(app.test_client())
    r = api.c.post("/api/v1/auth/logout", headers={"Origin": ORIGIN}, base_url=ORIGIN)
    assert r.status_code == 403 and r.get_json()["error"]["code"] == "csrf_failed"
    r = api.c.post("/api/v1/auth/logout", headers={"Origin": ORIGIN, "X-CSRF-Token": "x" * 64}, base_url=ORIGIN)
    assert r.status_code == 403
    assert db.session.scalar(select(AuditLog).where(AuditLog.event == "authz.denied")) is not None


@pytest.mark.parametrize("headers", [{}, {"Origin": "null"}, {"Origin": "https://evil.example"},
                                     {"Origin": ORIGIN, "Sec-Fetch-Site": "cross-site"}])
def test_origin_checks(app, headers):
    api = login(app.test_client())
    r = api.c.post("/api/v1/auth/logout", headers={**headers, "X-CSRF-Token": api.csrf}, base_url=ORIGIN)
    assert r.status_code == 403


def test_login_csrf_origin_check_applies_to_dev_login(client):
    r = client.post("/api/v1/auth/dev-login", json={"email": "a@b.c"}, headers={"Origin": "https://evil.example"},
                    base_url=ORIGIN)
    assert r.status_code == 403


# --- Cabeceras y errores -------------------------------------------------------------------------

def test_security_headers_on_api(api):
    h = api.get("/api/v1/auth/me").headers
    assert h["Content-Security-Policy"].startswith("default-src 'none'")
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["Cache-Control"] == "no-store"
    assert h["Referrer-Policy"] == "no-referrer"
    assert h["Strict-Transport-Security"].startswith("max-age=31536000")
    assert "charset=utf-8" in h["Content-Type"]
    assert "Access-Control-Allow-Origin" not in h
    assert len(h["X-Request-ID"]) >= 8


def test_unexpected_errors_are_generic(app):
    @app.get("/api/v1/_boom")
    def _boom():
        raise RuntimeError("detalle interno secreto")

    r = app.test_client().get("/api/v1/_boom", base_url=ORIGIN)
    assert r.status_code == 500
    body = r.get_data(as_text=True)
    assert "detalle interno" not in body and "RuntimeError" not in body
    assert r.get_json()["error"]["code"] == "internal_error" and r.get_json()["error"]["request_id"]


def test_unknown_route_is_json_404(client):
    r = client.get("/api/v1/no-existe", base_url=ORIGIN)
    assert r.status_code == 404 and r.get_json()["error"]["code"] == "not_found"


# --- Límites de peticiones ---------------------------------------------------------------------------

def test_auth_rate_limit():
    application = create_app(make_settings(ratelimit_enabled=True))
    with application.app_context():
        db.create_all()
        def fresh():  # cliente nuevo cada vez (sin cookie), misma IP
            return ApiClient(application.test_client())

        codes = [fresh().post("/api/v1/auth/dev-login", json={"email": f"u{i}@x.io"}).status_code for i in range(12)]
        assert codes[:10] == [200] * 10 and codes[-1] == 429
        r = fresh().post("/api/v1/auth/dev-login", json={"email": "z@x.io"})
        assert r.get_json()["error"]["code"] == "rate_limited" and r.headers.get("Retry-After")
        db.session.remove()
        db.drop_all()
