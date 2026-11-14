"""Auditoría de solo inserción (RNF-01): nunca se registran tokens ni código."""

from __future__ import annotations

import logging
from typing import Any

from flask import g, has_request_context, request

from ..extensions import db
from ..models.entities import AuditLog

log = logging.getLogger("api.audit")


def record(event: str, *, user_sub: str | None = None, target_type: str | None = None,
           target_id: object = None, outcome: str = "success", **details: Any) -> None:
    entry = AuditLog(event=event, user_sub=user_sub, target_type=target_type,
                     target_id=str(target_id) if target_id is not None else None, outcome=outcome,
                     details={k: v for k, v in details.items() if v is not None})
    if has_request_context():
        entry.ip = request.remote_addr
        entry.user_agent = (request.user_agent.string or "")[:400]
        entry.request_id = getattr(g, "request_id", None)
        if user_sub is None and getattr(g, "user", None) is not None:
            entry.user_sub = g.user.google_sub
    db.session.add(entry)
    log.info("audit %s", event, extra={"event": event})
