"""Autenticación OIDC (flujo de código + PKCE) y acceso de desarrollo.

Por defecto el proveedor es Google. Con OIDC_ISSUER se usa cualquier otro proveedor OIDC
(Microsoft Entra, Keycloak, el de la universidad): sus endpoints se leen del documento
de descubrimiento. El id_token se valida con `joserfc` contra las claves públicas (JWKS)
del proveedor.

Falla cerrado: sin cookie de login, con `state` distinto, `nonce` distinto o un
id_token inválido, el login no continúa (400 genérico). El usuario se
identifica por `sub`, nunca por email. Ver RFC 9700 y el BCP de OAuth para
aplicaciones de navegador (RFC 10017).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import requests
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select

from ..extensions import db
from ..models.entities import User

AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
LOGIN_COOKIE_MAX_AGE = 600
_JWKS_CACHE: dict[str, tuple[dict, float]] = {}
_DISCOVERY_CACHE: dict[str, tuple[dict, float]] = {}
CACHE_S = 3600


@dataclass(frozen=True)
class Provider:
    authorize_url: str
    token_url: str
    jwks_url: str
    issuers: frozenset[str]
    is_google: bool


GOOGLE = Provider(AUTHORIZE_URL, TOKEN_URL, JWKS_URL, frozenset(ISSUERS), True)


def provider(settings) -> Provider:
    """Google, o el proveedor de OIDC_ISSUER según su /.well-known/openid-configuration."""
    issuer = (settings.oidc_issuer or "").rstrip("/")
    if not issuer:
        return GOOGLE
    cached = _DISCOVERY_CACHE.get(issuer)
    if cached is None or time.time() - cached[1] > CACHE_S:
        try:
            resp = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=(5, 10))
            resp.raise_for_status()
            doc = resp.json()
        except (requests.RequestException, ValueError):
            raise AuthError("discovery_failed") from None
        # OIDC Discovery §4.3: el issuer del documento debe ser exactamente el configurado.
        if str(doc.get("issuer", "")).rstrip("/") != issuer:
            raise AuthError("discovery_issuer_mismatch")
        cached = (doc, time.time())
        _DISCOVERY_CACHE[issuer] = cached
    doc = cached[0]
    try:
        return Provider(doc["authorization_endpoint"], doc["token_endpoint"], doc["jwks_uri"],
                        frozenset({doc["issuer"]}), False)
    except KeyError:
        raise AuthError("discovery_incomplete") from None


class AuthError(Exception):
    """Fallo del flujo de login. El mensaje es genérico; el motivo va solo al log/auditoría."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class LoginState:
    state: str
    nonce: str
    verifier: str
    next_path: str


def login_cookie_name(settings) -> str:
    return "__Host-sast_login" if settings.is_secure else "sast_login"


def _serializer(settings) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.secret_key.get_secret_value(), salt="sast-login")


def safe_next(path: str | None) -> str:
    """Solo rutas relativas internas (evita redirecciones abiertas)."""
    if not path or not path.startswith("/") or path.startswith("//") or "\\" in path or ":" in path.split("?")[0]:
        return "/"
    return path[:300]


def redirect_uri(settings) -> str:
    return settings.oauth_redirect_uri or f"{settings.public_origin.rstrip('/')}/api/v1/auth/callback"


def start_login(settings, next_path: str | None) -> tuple[str, str]:
    """Devuelve (URL de autorización del proveedor, valor firmado para la cookie de login)."""
    prov = provider(settings)
    st = LoginState(secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64), safe_next(next_path))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(st.verifier.encode()).digest()).rstrip(b"=").decode()
    params = {
        "client_id": settings.google_client_id, "response_type": "code", "scope": "openid email profile",
        "redirect_uri": redirect_uri(settings), "state": st.state, "nonce": st.nonce,
        "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "select_account",
    }
    if prov.is_google and settings.google_hosted_domain:
        params["hd"] = settings.google_hosted_domain
    cookie = _serializer(settings).dumps({"s": st.state, "n": st.nonce, "v": st.verifier, "next": st.next_path})
    sep = "&" if "?" in prov.authorize_url else "?"
    return f"{prov.authorize_url}{sep}{urlencode(params)}", cookie


def read_login_cookie(settings, raw: str | None) -> LoginState:
    if not raw:
        raise AuthError("missing_login_cookie")
    try:
        data = _serializer(settings).loads(raw, max_age=LOGIN_COOKIE_MAX_AGE)
    except BadSignature:
        raise AuthError("bad_login_cookie") from None
    return LoginState(data["s"], data["n"], data["v"], safe_next(data.get("next")))


def exchange_code(settings, code: str, verifier: str) -> dict:
    resp = requests.post(provider(settings).token_url, data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(settings),
        "client_id": settings.google_client_id, "client_secret": settings.google_client_secret.get_secret_value(),
        "code_verifier": verifier,
    }, headers={"Accept": "application/json"}, timeout=(5, 15))
    if resp.status_code != 200:
        raise AuthError(f"token_endpoint_{resp.status_code}")
    return resp.json()


def fetch_jwks(url: str = JWKS_URL) -> dict:
    cached = _JWKS_CACHE.get(url)
    if cached is None or time.time() - cached[1] > CACHE_S:
        resp = requests.get(url, timeout=(5, 10))
        resp.raise_for_status()
        cached = (resp.json(), time.time())
        _JWKS_CACHE[url] = cached
    return cached[0]


def validate_id_token(settings, id_token: str, nonce: str) -> dict:
    prov = provider(settings)
    try:
        keys = KeySet.import_key_set(fetch_jwks(prov.jwks_url))
        token = jwt.decode(id_token, keys, algorithms=["RS256"])
        registry = jwt.JWTClaimsRegistry(
            leeway=60,
            iss={"essential": True, "values": sorted(prov.issuers)},
            aud={"essential": True, "value": settings.google_client_id},
            exp={"essential": True},
            sub={"essential": True},
        )
        registry.validate(token.claims)
        claims = token.claims
    except (JoseError, ValueError, KeyError, TypeError, requests.RequestException):
        raise AuthError("invalid_id_token") from None
    if claims.get("nonce") != nonce:
        raise AuthError("nonce_mismatch")
    # Google siempre manda email_verified. Otros proveedores (p. ej. Microsoft Entra) no lo
    # incluyen: ahí solo se rechaza si viene en falso. La identidad es `sub`, no el email.
    if prov.is_google and not claims.get("email_verified"):
        raise AuthError("email_not_verified")
    if not prov.is_google and claims.get("email_verified") is False:
        raise AuthError("email_not_verified")
    if prov.is_google and settings.google_hosted_domain and claims.get("hd") != settings.google_hosted_domain:
        raise AuthError("hosted_domain_mismatch")
    return dict(claims)


def complete_login(settings, *, code: str | None, state: str | None, login: LoginState) -> User:
    if not code or not state or not secrets.compare_digest(state, login.state):
        raise AuthError("state_mismatch")
    tokens = exchange_code(settings, code, login.verifier)
    claims = validate_id_token(settings, tokens.get("id_token", ""), login.nonce)
    # El `sub` solo es único dentro de su emisor: con otro proveedor se antepone el issuer.
    prefix = "google" if provider(settings).is_google else (settings.oidc_issuer or "").rstrip("/")
    email = claims.get("email") or claims.get("preferred_username", "")
    return upsert_user(f"{prefix}|{claims['sub']}", email, claims.get("name") or email)


def upsert_user(sub: str, email: str, name: str) -> User:
    user = db.session.scalar(select(User).where(User.google_sub == sub))
    if user is None:
        user = User(google_sub=sub, email=email, name=name[:200])
        db.session.add(user)
    else:
        user.email, user.name = email, name[:200]
    db.session.flush()
    return user
