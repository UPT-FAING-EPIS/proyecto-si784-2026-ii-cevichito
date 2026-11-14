"""Errores genéricos y estables (RNF-01): nunca se envía el texto interno de la excepción."""

from __future__ import annotations

import logging

from flask import Flask, g, jsonify
from werkzeug.exceptions import HTTPException

log = logging.getLogger("api.errors")

_HTTP_CODES = {
    400: ("bad_request", "Petición inválida."),
    401: ("unauthenticated", "Se requiere iniciar sesión."),
    403: ("forbidden", "Operación no permitida."),
    404: ("not_found", "Recurso no encontrado."),
    405: ("method_not_allowed", "Método no permitido."),
    409: ("conflict", "El recurso está en un estado que no permite la operación."),
    413: ("payload_too_large", "El contenido supera el tamaño máximo permitido."),
    415: ("unsupported_media_type", "Tipo de contenido no soportado."),
    422: ("unprocessable", "Los datos no son válidos."),
    429: ("rate_limited", "Demasiadas peticiones. Inténtalo más tarde."),
    500: ("internal_error", "Error interno. Si persiste, informa el request_id."),
    503: ("unavailable", "Servicio no disponible temporalmente."),
}


class ApiError(Exception):
    """Error de negocio con código estable para el cliente."""

    def __init__(self, status: int, code: str | None = None, message: str | None = None, **details) -> None:
        default_code, default_msg = _HTTP_CODES.get(status, ("error", "Error."))
        super().__init__(code or default_code)
        self.status = status
        self.code = code or default_code
        self.message = message or default_msg
        self.details = details


def error_body(status: int, code: str, message: str, details: dict | None = None):
    body = {"error": {"code": code, "message": message, "request_id": getattr(g, "request_id", None)}}
    if details:
        body["error"]["details"] = details
    resp = jsonify(body)
    resp.status_code = status
    return resp


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(ApiError)
    def _api_error(exc: ApiError):
        return error_body(exc.status, exc.code, exc.message, exc.details or None)

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):
        code, message = _HTTP_CODES.get(exc.code or 500, ("error", "Error."))
        resp = error_body(exc.code or 500, code, message)
        if exc.code == 429 and getattr(exc, "retry_after", None):
            resp.headers["Retry-After"] = str(exc.retry_after)
        return resp

    @app.errorhandler(Exception)
    def _unexpected(exc: Exception):
        log.exception("error no controlado")
        code, message = _HTTP_CODES[500]
        return error_body(500, code, message)
