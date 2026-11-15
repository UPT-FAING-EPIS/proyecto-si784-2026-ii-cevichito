"""Modelo de datos (sección 4.3 de la especificación).

- Un *issue* persistente por huella y proyecto, y una *ocurrencia* por escaneo
  (modelo de SonarQube).
- El ciclo de vida (`lifecycle`: lo decide el sistema) está separado del
  triage (`triage`: lo deciden las personas).
- Los estados son VARCHAR + CHECK (más fáciles de migrar que los ENUM nativos).
- Tipos portables: UUID, JSON (JSONB en PostgreSQL) y listas en JSON, para que
  los tests unitarios puedan usar SQLite y producción PostgreSQL.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON, BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, LargeBinary,
    SmallInteger, String, Text, UniqueConstraint, Uuid,
)
from sqlalchemy import false as sa_false
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..extensions import db

JSONType = JSON().with_variant(JSONB(), "postgresql")
BigIntPK = BigInteger().with_variant(Integer(), "sqlite")

SCAN_STATUSES = ("queued", "running", "done", "failed", "canceled")
SCAN_SOURCES = ("snippet", "zip", "github")
LIFECYCLES = ("open", "fixed", "reopened")
TRIAGES = ("untriaged", "confirmed", "false_positive", "accepted", "wont_fix")
CHANGES = ("new", "persisting", "reopened")
EVENT_KINDS = ("lifecycle", "triage", "comment")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class User(db.Model):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    google_sub: Mapped[str] = mapped_column(String(255), unique=True)
    email: Mapped[str] = mapped_column(String(320))
    name: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuthSession(db.Model):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_secret: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))

    user: Mapped[User] = relationship()


class Project(db.Model):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("owner_id", "name", name="uq_projects_owner_name"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Un intento de reto es un proyecto oculto del alumno (no aparece en el panel de proyectos).
    challenge_id: Mapped[str | None] = mapped_column(String(80), index=True)
    challenge_solved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RuleRecord(db.Model):
    """Copia del catálogo del motor, sincronizada al arrancar (para FK y métricas)."""

    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    tool: Mapped[str] = mapped_column(String(40), default="sast-studio")
    name: Mapped[str] = mapped_column(String(200))
    default_severity: Mapped[int] = mapped_column(SmallInteger)
    confidence: Mapped[int] = mapped_column(SmallInteger)
    cwe: Mapped[list[str]] = mapped_column(JSONType, default=list)
    owasp: Mapped[list[str]] = mapped_column(JSONType, default=list)
    kind: Mapped[str] = mapped_column(String(20))
    engine: Mapped[str] = mapped_column(String(20))
    previous_ids: Mapped[list[str]] = mapped_column(JSONType, default=list)
    meta: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    version: Mapped[str] = mapped_column(String(20))


class Scan(db.Model):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(_in("status", SCAN_STATUSES), name="status"),
        CheckConstraint(_in("source", SCAN_SOURCES), name="source"),
        Index("ix_scans_queue", "status", "queued_at"),
        Index("ix_scans_stream", "project_id", "category", "finished_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(10))
    source_ref: Mapped[str] = mapped_column(String(300), default="")
    category: Mapped[str] = mapped_column(String(80), default="default")
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(10), default="queued")
    progress_done: Mapped[int] = mapped_column(Integer, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, default=0)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    worker_id: Mapped[str | None] = mapped_column(String(80))
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(40))
    rules_enabled: Mapped[list[str]] = mapped_column(JSONType, default=list)
    rules_requested: Mapped[list[str] | None] = mapped_column(JSONType)
    engine_version: Mapped[str | None] = mapped_column(String(20))
    loc_total: Mapped[int] = mapped_column(Integer, default=0)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    rule_errors: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    baseline_scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    request_id: Mapped[str | None] = mapped_column(String(64))
    # Se acabó el tiempo y solo se analizó una parte (los archivos sin analizar no se dan por corregidos).
    partial: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    # El resultado salió de la caché: otro escaneo analizó exactamente el mismo contenido.
    result_reused: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())

    project: Mapped[Project] = relationship()

    @property
    def finished(self) -> bool:
        return self.status in {"done", "failed", "canceled"}


class ScanResultCache(db.Model):
    """Resultado del motor para un contenido concreto, para no analizarlo dos veces.

    La clave es un hash del contenido analizado, la versión del motor y las reglas pedidas: solo
    coincide quien tiene exactamente el mismo código, así que reutilizarlo no expone nada.
    Se guardan los hallazgos y el código solo de los archivos con hallazgos (comprimido).
    """

    __tablename__ = "scan_result_cache"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)


class ScanUpload(db.Model):
    """Contenido subido, guardado solo mientras el escaneo está pendiente (RNF-01)."""

    __tablename__ = "scan_uploads"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True)
    content: Mapped[bytes] = mapped_column(LargeBinary)
    filename: Mapped[str] = mapped_column(String(255), default="")
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Issue(db.Model):
    __tablename__ = "issues"
    __table_args__ = (
        CheckConstraint(_in("lifecycle", LIFECYCLES), name="lifecycle"),
        CheckConstraint(_in("triage", TRIAGES), name="triage"),
        UniqueConstraint("project_id", "category", "fingerprint_version", "fingerprint", name="uq_issues_fingerprint"),
        Index("ix_issues_project_state", "project_id", "lifecycle", "severity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("rules.id"))
    category: Mapped[str] = mapped_column(String(80), default="default")
    fingerprint: Mapped[str] = mapped_column(String(64))
    fingerprint_version: Mapped[int] = mapped_column(SmallInteger, default=1)
    line_hash: Mapped[str] = mapped_column(String(64), default="")
    snippet_hash: Mapped[str] = mapped_column(String(64), default="")
    lifecycle: Mapped[str] = mapped_column(String(10), default="open")
    triage: Mapped[str] = mapped_column(String(16), default="untriaged")
    triage_justification: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[int] = mapped_column(SmallInteger)
    current_path: Mapped[str] = mapped_column(String(500))
    current_line: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(Text, default="")
    first_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reopened_count: Mapped[int] = mapped_column(Integer, default=0)
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class Occurrence(db.Model):
    __tablename__ = "occurrences"
    __table_args__ = (
        CheckConstraint(_in("change", CHANGES), name="change"),
        UniqueConstraint("scan_id", "issue_id", name="uq_occurrences_scan_issue"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    issue_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("issues.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(String(500))
    start_line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int] = mapped_column(Integer)
    start_col: Mapped[int] = mapped_column(Integer, default=0)
    end_col: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[int] = mapped_column(SmallInteger)
    confidence: Mapped[int] = mapped_column(SmallInteger)
    snippet: Mapped[str] = mapped_column(Text, default="")
    line_hash: Mapped[str] = mapped_column(String(64), default="")
    trace: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    variant: Mapped[str | None] = mapped_column(String(200))
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    suppression_reason: Mapped[str | None] = mapped_column(String(500))
    change: Mapped[str] = mapped_column(String(10), default="new")

    issue: Mapped[Issue] = relationship()


class IssueEvent(db.Model):
    __tablename__ = "issue_events"
    __table_args__ = (
        CheckConstraint(_in("kind", EVENT_KINDS), name="kind"),
        Index("ix_issue_events_issue_created", "issue_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    issue_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("issues.id", ondelete="CASCADE"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(10))
    from_state: Mapped[str | None] = mapped_column(String(20))
    to_state: Mapped[str | None] = mapped_column(String(20))
    comment: Mapped[str | None] = mapped_column(Text)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(db.Model):
    """Registro de auditoría de solo inserción (RNF-01)."""

    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_log_user_at", "user_sub", "at"),)

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    event: Mapped[str] = mapped_column(String(60))
    user_sub: Mapped[str | None] = mapped_column(String(255))
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))
    request_id: Mapped[str | None] = mapped_column(String(64))
    target_type: Mapped[str | None] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(20), default="success")
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
