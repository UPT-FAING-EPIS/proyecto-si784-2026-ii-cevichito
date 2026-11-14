"""Seguridad transversal: sesión BFF, CSRF y cabeceras."""

from flask import Flask

from .csrf import init_csrf
from .headers import init_headers
from .session import init_session


def init_security(app: Flask) -> None:
    init_session(app)   # primero: carga g.user / g.session
    init_csrf(app)      # después: necesita la sesión para validar el token
    init_headers(app)
