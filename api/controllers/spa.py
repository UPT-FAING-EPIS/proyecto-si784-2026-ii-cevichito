"""Sirve la SPA compilada desde el mismo origen que la API (decisión D2 de la especificación).

Así la cookie de sesión `__Host-` funciona sin CORS ni cookies de terceros.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, abort, send_from_directory

RESERVED = ("api/", "healthz", "readyz")


def register_spa(app: Flask) -> None:
    spa_dir = app.config["SETTINGS"].spa_dir
    if not spa_dir or not (Path(spa_dir) / "index.html").is_file():
        return
    root = str(Path(spa_dir).resolve())

    @app.get("/", defaults={"path": ""}, endpoint="spa_index")
    @app.get("/<path:path>", endpoint="spa")
    def spa(path: str):
        if path.startswith(RESERVED):
            abort(404)
        candidate = Path(root, path)
        if path and candidate.is_file():
            resp = send_from_directory(root, path, max_age=31536000 if path.startswith("assets/") else 0)
        else:
            resp = send_from_directory(root, "index.html", max_age=0)
        return resp
