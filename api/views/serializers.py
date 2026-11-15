"""Serializadores: cada respuesta se construye con campos en lista blanca (RNF-01, API3)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sast.rules.api import Confidence, RuleMeta, Severity

from ..models.entities import Issue, IssueEvent, Occurrence, Project, Scan, User


def iso_utc(value: datetime | None) -> str | None:
    """ISO 8601 siempre con zona. Todas las fechas se guardan en UTC, pero SQLite
    las devuelve sin zona y el navegador las leería como hora local."""
    if not value:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


_dt = iso_utc


def me(user: User, csrf_token: str) -> dict[str, Any]:
    return {"id": str(user.id), "email": user.email, "name": user.name, "csrf_token": csrf_token}


def public_config(settings, version: str) -> dict[str, Any]:
    return {
        "version": version,
        "auth": {
            "oidc": bool(settings.google_client_id and settings.google_client_secret),
            "google": bool(settings.google_client_id and settings.google_client_secret),  # alias anterior
            "provider": settings.provider_name,
            "dev_login": bool(settings.dev_login_enabled and settings.environment != "prod"),
        },
        "limits": {
            "max_upload_mb": settings.max_upload_mb,
            "max_snippet_kb": settings.max_snippet_kb,
            "max_zip_entries": settings.max_zip_entries,
            "max_total_uncompressed_mb": settings.max_total_uncompressed_mb,
            "max_compression_ratio": settings.max_compression_ratio,
            "github_max_mb": settings.github_max_mb,
            "scan_timeout_s": settings.scan_timeout_s,
            "scans_per_hour": settings.scans_per_hour,
            "retention_days": settings.retention_days,
        },
    }


def rule(meta: RuleMeta) -> dict[str, Any]:
    return {
        "id": meta.id, "name": meta.name, "severity": meta.severity.label, "confidence": meta.confidence.label,
        "cwe": list(meta.cwe), "owasp": list(meta.owasp), "kind": meta.kind, "languages": list(meta.languages),
        "engine": meta.engine, "security_severity": meta.security_severity, "message": meta.message,
        "explanation_es": meta.explanation, "remediation_es": meta.remediation, "example_bad": meta.example_bad,
        "example_good": meta.example_good, "references": list(meta.references),
    }


def scan_summary(scan: Scan | None) -> dict[str, Any] | None:
    if scan is None:
        return None
    return {"id": str(scan.id), "status": scan.status, "finished_at": _dt(scan.finished_at), "summary": scan.summary or {}}


def project(p: Project, last_scan: Scan | None = None, open_counts: dict[str, int] | None = None) -> dict[str, Any]:
    out = {"id": str(p.id), "name": p.name, "created_at": _dt(p.created_at), "last_scan": scan_summary(last_scan)}
    if open_counts is not None:
        out["open_by_severity"] = open_counts
    return out


def scan(s: Scan, queue: dict | None = None) -> dict[str, Any]:
    """`queue` (posición y estimación) solo se calcula al pedir un escaneo concreto."""
    return {
        "id": str(s.id), "project_id": str(s.project_id), "status": s.status, "source": s.source,
        "source_ref": s.source_ref, "category": s.category, "commit_sha": s.commit_sha,
        "progress": {"files_done": s.progress_done, "files_total": s.progress_total},
        "queued_at": _dt(s.queued_at), "started_at": _dt(s.started_at), "finished_at": _dt(s.finished_at),
        "summary": s.summary or {}, "rule_errors": s.rule_errors or [], "error_code": s.error_code,
        "cancel_requested": s.cancel_requested, "files_scanned": s.files_scanned, "loc_total": s.loc_total,
        "engine_version": s.engine_version, "baseline_scan_id": str(s.baseline_scan_id) if s.baseline_scan_id else None,
        "rules_requested": s.rules_requested,
        "partial": bool(s.partial), "result_reused": bool(s.result_reused), "queue": queue,
    }


def occurrence(o: Occurrence) -> dict[str, Any]:
    issue = o.issue
    return {
        "occurrence_id": str(o.id), "issue_id": str(o.issue_id), "rule_id": issue.rule_id,
        "severity": Severity(o.severity).label, "confidence": Confidence(o.confidence).label,
        "path": o.path, "start_line": o.start_line, "end_line": o.end_line, "start_col": o.start_col,
        "message": o.message, "snippet": o.snippet, "trace": o.trace or [], "variant": o.variant,
        "change": o.change, "triage": issue.triage, "lifecycle": issue.lifecycle, "suppressed": o.suppressed,
        "suppression_reason": o.suppression_reason,
    }


def issue(i: Issue, last: Occurrence | None = None, rule_meta: RuleMeta | None = None) -> dict[str, Any]:
    out = {
        "id": str(i.id), "project_id": str(i.project_id), "rule_id": i.rule_id, "category": i.category,
        "lifecycle": i.lifecycle, "triage": i.triage, "triage_justification": i.triage_justification,
        "severity": Severity(i.severity).label, "path": i.current_path, "line": i.current_line,
        "message": i.message, "first_seen_at": _dt(i.first_seen_at), "fixed_at": _dt(i.fixed_at),
        "first_seen_scan_id": str(i.first_seen_scan_id) if i.first_seen_scan_id else None,
        "last_seen_scan_id": str(i.last_seen_scan_id) if i.last_seen_scan_id else None,
        "reopened_count": i.reopened_count, "fingerprint": i.fingerprint,
    }
    if last is not None:
        out["last_occurrence"] = occurrence(last)
    if rule_meta is not None:
        out["rule"] = rule(rule_meta)
    return out


def event(e: IssueEvent, users: dict) -> dict[str, Any]:
    u = users.get(e.user_id)
    return {"kind": e.kind, "from": e.from_state, "to": e.to_state, "comment": e.comment,
            "user": {"id": str(u.id), "name": u.name} if u else None,
            "scan_id": str(e.scan_id) if e.scan_id else None, "created_at": _dt(e.created_at)}
