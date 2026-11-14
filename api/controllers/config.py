"""Configuración pública que necesita la interfaz antes de iniciar sesión: /api/v1/config.

Solo expone qué métodos de acceso están activos y los límites de subida que la interfaz
muestra al usuario (RF-23). Nada secreto: ni identificadores de cliente ni URLs internas.
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from sast import __version__

from ..views import serializers

bp = Blueprint("config", __name__, url_prefix="/api/v1")


@bp.get("/config")
def public_config():
    settings = current_app.config["SETTINGS"]
    return jsonify(serializers.public_config(settings, __version__))
