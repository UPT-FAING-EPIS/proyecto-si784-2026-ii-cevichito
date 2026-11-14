"""Fábrica de la aplicación (application factory) y wiring MVC."""

from __future__ import annotations

from pathlib import Path

from flask import Flask
from sqlalchemy import event
from sqlalchemy.engine import Engine as SAEngine

from .errors import register_error_handlers
from .extensions import db, limiter, migrate
from .logging_setup import configure_logging, init_request_id
from .settings import Settings

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


@event.listens_for(SAEngine, "connect")
def _sqlite_foreign_keys(dbapi_conn, _record):  # pragma: no cover - solo SQLite
    if type(dbapi_conn).__module__.startswith("sqlite3"):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


def _engine_options(settings: Settings) -> dict:
    if settings.database_url.startswith("sqlite"):
        return {}
    return {"pool_pre_ping": True, "pool_size": settings.db_pool_size, "max_overflow": settings.db_max_overflow,
            "pool_recycle": 1800}


def create_app(settings: Settings | None = None) -> Flask:
    settings = settings or Settings()
    configure_logging(settings.log_level)

    app = Flask(__name__, static_folder=None)
    app.config.update(
        SETTINGS=settings,
        SECRET_KEY=settings.secret_key.get_secret_value(),
        SQLALCHEMY_DATABASE_URI=settings.database_url,
        SQLALCHEMY_ENGINE_OPTIONS=_engine_options(settings),
        MAX_CONTENT_LENGTH=settings.max_upload_mb * 1024 * 1024 + 64 * 1024,
        RATELIMIT_STORAGE_URI=settings.ratelimit_storage_uri,
        RATELIMIT_ENABLED=settings.ratelimit_enabled,
        JSON_SORT_KEYS=False,
        TESTING=settings.environment == "test",
    )
    if settings.trust_proxy:
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=settings.proxy_hops, x_proto=1, x_host=1)  # type: ignore[method-assign]

    db.init_app(app)
    migrate.init_app(app, db, directory=str(MIGRATIONS_DIR))
    limiter.init_app(app)
    init_request_id(app)
    register_error_handlers(app)

    from .security import init_security

    init_security(app)

    from . import models  # noqa: F401  (registra los modelos en el metadata)
    from .controllers import register_blueprints

    register_blueprints(app)
    return app
