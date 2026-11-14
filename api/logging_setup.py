"""Logs estructurados en JSON por stdout, con `request_id` (RNF-01 trazabilidad)."""

from __future__ import annotations

import json
import logging
import sys
import uuid
from datetime import datetime, timezone

from flask import Flask, g, has_request_context, request

_REQUEST_ID_HEADER = "X-Request-ID"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        rid = getattr(record, "request_id", None)
        if rid is None and has_request_context():
            rid = getattr(g, "request_id", None)
        if rid:
            data["request_id"] = rid
        for key in ("scan_id", "event", "path", "status", "duration_ms", "worker_id"):
            if hasattr(record, key):
                data[key] = getattr(record, key)
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.handlers = [handler]
    root.setLevel(level.upper())


def _valid_request_id(value: str | None) -> str | None:
    if value and 8 <= len(value) <= 64 and all(c.isalnum() or c in "-_" for c in value):
        return value
    return None


def init_request_id(app: Flask) -> None:
    access = logging.getLogger("api.access")

    @app.before_request
    def _assign():
        g.request_id = _valid_request_id(request.headers.get(_REQUEST_ID_HEADER)) or uuid.uuid4().hex
        g.request_started = datetime.now(timezone.utc)

    @app.after_request
    def _emit(resp):
        rid = getattr(g, "request_id", None)
        if rid:
            resp.headers[_REQUEST_ID_HEADER] = rid
            started = getattr(g, "request_started", None)
            ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000) if started else None
            access.info("%s %s", request.method, request.path,
                        extra={"path": request.path, "status": resp.status_code, "duration_ms": ms})
        return resp
