"""Informes de un escaneo (SARIF 2.1.0, JSON y HTML) reconstruidos desde la base de datos."""

from __future__ import annotations

import json

from sqlalchemy import select

from sast.engine.runner import ScanReport
from sast.reports import render_html, to_sarif
from sast.rules.api import Confidence, Finding, RuleError, Severity, TraceStep
from sast.rules.registry import default_ruleset

from ..extensions import db
from ..models.entities import Issue, Occurrence, Scan
from ..views import serializers
from .metrics_service import scan_diff

_BASELINE = {"new": "new", "persisting": "unchanged", "reopened": "unchanged"}


def _finding(o: Occurrence, issue: Issue) -> Finding:
    return Finding(
        rule_id=issue.rule_id, path=o.path, line=o.start_line, col=o.start_col, end_line=o.end_line,
        end_col=o.end_col, message=o.message, severity=Severity(o.severity), confidence=Confidence(o.confidence),
        trace=tuple(TraceStep(t["line"], t["description"]) for t in (o.trace or [])), variant=o.variant,
        suppressed=o.suppressed, suppression_reason=o.suppression_reason, snippet=o.snippet,
        fingerprint=issue.fingerprint,
    )


def _report(scan: Scan, occurrences: list[Occurrence]) -> ScanReport:
    return ScanReport(
        target=scan.source_ref, findings=[_finding(o, o.issue) for o in occurrences],
        rule_errors=[RuleError(**e) for e in scan.rule_errors or []], files_scanned=scan.files_scanned,
        loc_total=scan.loc_total, rules_enabled=scan.rules_enabled or [], engine_version=scan.engine_version or "",
        started_at=serializers.iso_utc(scan.started_at) or "",
        finished_at=serializers.iso_utc(scan.finished_at),
    )


def occurrences_for(scan: Scan) -> list[Occurrence]:
    return list(db.session.scalars(select(Occurrence).where(Occurrence.scan_id == scan.id)
                                   .order_by(Occurrence.path, Occurrence.start_line, Occurrence.start_col)))


def sarif(scan: Scan) -> dict:
    occs = occurrences_for(scan)
    report = _report(scan, occs)
    states = {o.issue.fingerprint: _BASELINE[o.change] for o in occs}
    absent = []
    if scan.baseline_scan_id:
        base = db.session.get(Scan, scan.baseline_scan_id)
        if base is not None:
            absent = [_finding(o, o.issue) for o in scan_diff(scan, base)["fixed"]]
    triage = {o.issue.fingerprint: {"triage": o.issue.triage, "justification": o.issue.triage_justification or ""}
              for o in occs}
    metas = default_ruleset().metas()
    return to_sarif(report, metas, baseline_states=states, absent=absent, triage=triage,
                    automation_id=f"sast-studio/{scan.category}/{scan.id}")


def as_json(scan: Scan) -> dict:
    return {"scan": serializers.scan(scan), "findings": [serializers.occurrence(o) for o in occurrences_for(scan)]}


def html(scan: Scan) -> str:
    return render_html(_report(scan, occurrences_for(scan)), default_ruleset().metas())


def render(scan: Scan, fmt: str) -> tuple[str, str, str]:
    """Devuelve (contenido, mimetype, extensión)."""
    if fmt == "sarif":
        return json.dumps(sarif(scan), indent=2, ensure_ascii=False), "application/sarif+json", "sarif"
    if fmt == "html":
        return html(scan), "text/html", "html"
    return json.dumps(as_json(scan), indent=2, ensure_ascii=False), "application/json", "json"
