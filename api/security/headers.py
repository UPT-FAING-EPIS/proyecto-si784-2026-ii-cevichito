"""Cabeceras de seguridad en todas las respuestas (RNF-01)."""

from __future__ import annotations

from flask import Flask, current_app, request

API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
SPA_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data: https://lh3.googleusercontent.com; font-src 'self'; connect-src 'self'; "
           "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def init_headers(app: Flask) -> None:
    @app.after_request
    def _apply(resp):
        settings = current_app.config["SETTINGS"]
        is_api = request.path.startswith(("/api/", "/healthz", "/readyz"))
        h = resp.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "no-referrer"
        h["X-Frame-Options"] = "DENY"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if settings.is_secure:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if is_api:
            h["Content-Security-Policy"] = API_CSP
            h.setdefault("Cache-Control", "no-store")
        else:
            h["Content-Security-Policy"] = SPA_CSP
        h.pop("Server", None)
        if resp.mimetype in {"application/json", "text/html", "text/plain"} and "charset" not in (resp.content_type or ""):
            resp.content_type = f"{resp.mimetype}; charset=utf-8"
        return resp
