# -*- coding: utf-8 -*-
"""Controladores (blueprints finos): validan la entrada, llaman a servicios y serializan con vistas."""

from __future__ import annotations

from flask import Flask


def register_blueprints(app: Flask) -> None:
    from . import auth, challenges, config, health, issues, legacy, projects, rules, scans, usage
    from .spa import register_spa

    for module in (health, config, auth, rules, projects, scans, issues, challenges, usage, legacy):
        app.register_blueprint(module.bp)
    register_spa(app)
