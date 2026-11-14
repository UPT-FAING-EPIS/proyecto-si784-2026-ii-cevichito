"""Punto de entrada WSGI (gunicorn api.wsgi:app) y de `flask db ...`."""

from .factory import create_app

app = create_app()
