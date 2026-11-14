"""Formatos de salida: consola, JSON, SARIF 2.1.0 y HTML."""

from .console import render_console
from .html import render_html
from .sarif import to_sarif

__all__ = ["render_console", "render_html", "to_sarif"]
