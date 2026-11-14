"""Autorización por objeto (RNF-01, OWASP API1 BOLA).

Toda consulta de proyecto, escaneo o issue se filtra por el dueño en la capa
de servicios. Si el recurso no existe **o no es del usuario**, se responde 404
(no 403), para no revelar qué IDs existen.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select

from ..errors import ApiError
from ..extensions import db
from ..models.entities import Issue, Project, Scan, User


def parse_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        raise ApiError(404) from None


def project_of(user: User, project_id: str) -> Project:
    p = db.session.scalar(select(Project).where(Project.id == parse_uuid(project_id), Project.owner_id == user.id))
    if p is None:
        raise ApiError(404)
    return p


def scan_of(user: User, scan_id: str) -> Scan:
    s = db.session.scalar(select(Scan).join(Project, Scan.project_id == Project.id)
                          .where(Scan.id == parse_uuid(scan_id), Project.owner_id == user.id))
    if s is None:
        raise ApiError(404)
    return s


def issue_of(user: User, issue_id: str) -> Issue:
    i = db.session.scalar(select(Issue).join(Project, Issue.project_id == Project.id)
                          .where(Issue.id == parse_uuid(issue_id), Project.owner_id == user.id))
    if i is None:
        raise ApiError(404)
    return i
