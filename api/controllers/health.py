"""Salud del servicio (RNF-04): `/healthz` (vivo) y `/readyz` (BD y migraciones al día)."""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify
from sqlalchemy import text

from ..extensions import db, limiter

bp = Blueprint("health", __name__)
log = logging.getLogger("api.health")


def _migration_state() -> tuple[str | None, str | None]:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    from ..factory import MIGRATIONS_DIR

    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    head = ScriptDirectory.from_config(cfg).get_current_head()
    try:
        current = db.session.execute(text("SELECT version_num FROM alembic_version")).scalar()
    except Exception:
        db.session.rollback()
        current = None
    return current, head


@bp.get("/healthz")
@limiter.exempt
def healthz():
    return jsonify({"status": "ok"})


@bp.get("/readyz")
@limiter.exempt
def readyz():
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        log.warning("readyz: base de datos no disponible", exc_info=True)
        return jsonify({"db": "error", "migrations": "unknown"}), 503
    current, head = _migration_state()
    if current != head:
        return jsonify({"db": "ok", "migrations": "pending", "current": current, "head": head}), 503
    return jsonify({"db": "ok", "migrations": "head"})
