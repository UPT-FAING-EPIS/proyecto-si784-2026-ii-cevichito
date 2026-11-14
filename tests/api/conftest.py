"""Fixtures de la API nueva.

Por defecto usan SQLite en memoria. Con `TEST_DATABASE_URL` (p. ej. el Postgres
de docker compose o del CI) las mismas pruebas corren contra PostgreSQL real,
aplicando las migraciones de Alembic.
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import text

from api.extensions import db
from api.factory import create_app
from api.models.entities import Project, User
from api.settings import Settings

PG_URL = os.environ.get("TEST_DATABASE_URL")


def make_settings(**overrides) -> Settings:
    base = dict(
        environment="test",
        secret_key="test-secret-key-0123456789abcdefghij",
        session_hmac_key="test-hmac-key-0123456789abcdefghijk",
        database_url=PG_URL or "sqlite://",
        dev_login_enabled=True,
        public_origin="https://sast.test",
        ratelimit_enabled=False,
    )
    base.update(overrides)
    return Settings(_env_file=None, **base)


@pytest.fixture
def app():
    application = create_app(make_settings())
    with application.app_context():
        if PG_URL:
            from flask_migrate import upgrade

            db.session.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
            db.session.commit()
            upgrade()
        else:
            db.create_all()
        from api.services.issue_service import sync_rules
        from sast import __version__
        from sast.rules.registry import default_ruleset

        sync_rules(default_ruleset(), __version__)
        db.session.commit()
        yield application
        db.session.remove()
        if not PG_URL:
            db.drop_all()


ORIGIN = "https://sast.test"


@pytest.fixture
def client(app):
    return app.test_client()


class ApiClient:
    """Cliente de pruebas que actúa como la SPA: mismo origen, cookie de sesión y X-CSRF-Token."""

    def __init__(self, flask_client, csrf: str | None = None) -> None:
        self.c = flask_client
        self.csrf = csrf

    def _headers(self, kw):
        h = dict(kw.pop("headers", None) or {})
        h.setdefault("Origin", ORIGIN)
        if self.csrf:
            h.setdefault("X-CSRF-Token", self.csrf)
        kw["headers"] = h
        kw.setdefault("base_url", ORIGIN)
        return kw

    def get(self, url, **kw):
        return self.c.get(url, **self._headers(kw))

    def post(self, url, **kw):
        return self.c.post(url, **self._headers(kw))

    def patch(self, url, **kw):
        return self.c.patch(url, **self._headers(kw))

    def delete(self, url, **kw):
        return self.c.delete(url, **self._headers(kw))


def login(flask_client, email="ana@example.com") -> ApiClient:
    api = ApiClient(flask_client)
    r = api.post("/api/v1/auth/dev-login", json={"email": email, "name": email.split("@")[0]})
    assert r.status_code == 200, r.get_json()
    api.csrf = r.get_json()["csrf_token"]
    return api


@pytest.fixture
def api(app):
    return login(app.test_client())


@pytest.fixture
def user(app) -> User:
    u = User(google_sub=f"test|{uuid.uuid4().hex}", email="ana@example.com", name="Ana")
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture
def project(app, user) -> Project:
    p = Project(owner_id=user.id, name="demo")
    db.session.add(p)
    db.session.commit()
    return p
