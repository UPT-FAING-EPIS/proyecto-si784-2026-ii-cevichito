"""Persistencia de resultados: emparejado de hallazgos con issues y ciclo de vida.

Emparejador multipaso (por proyecto y flujo/`category`):
  1. huella exacta `sastfp/v1`;
  2. (regla o `previous_ids`, ruta normalizada, hash de línea);
  3. (regla, ruta, mensaje, línea ±3);
  4. (regla, hash del fragmento) en otro archivo: detecta renombres.

Ciclo de vida (lo decide el sistema, nunca toca el triage):
  - hallazgo sin issue -> issue nuevo `open` (cambio `new`);
  - issue `fixed` que reaparece -> `reopened` (salvo falso positivo);
  - issue abierto que no aparece -> `fixed`, solo si su regla estaba activa en
    el escaneo y su archivo estaba en el alcance (así desactivar una regla no
    cuenta como "corregido").
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select

from sast.engine.fingerprint import VERSION as FP_VERSION
from sast.engine.fingerprint import line_hash, normalize_path, snippet_hash
from sast.engine.runner import ScanReport
from sast.rules.api import Finding
from sast.rules.registry import RuleSet

from ..extensions import db
from ..models.entities import Issue, IssueEvent, Occurrence, RuleRecord, Scan, utcnow

MAX_SNIPPET = 4096
_STRING = re.compile(r"""("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')""")
FULL_SCOPE_SOURCES = {"zip", "github"}


def redact(snippet: str, rule_id: str) -> str:
    """Oculta literales en fragmentos de reglas de secretos antes de guardarlos."""
    text = snippet[:MAX_SNIPPET]
    if rule_id == "generic/hardcoded-secret":
        text = _STRING.sub(lambda m: m.group(0)[0] + "•••" + m.group(0)[0], text)
    return text


@dataclass
class IngestResult:
    new: int = 0
    persisting: int = 0
    reopened: int = 0
    fixed: int = 0


def sync_rules(ruleset: RuleSet, version: str) -> None:
    """Copia el catálogo del motor a la tabla `rules` (idempotente)."""
    existing = {r.id: r for r in db.session.scalars(select(RuleRecord))}
    for m in ruleset.metas():
        rec = existing.get(m.id) or RuleRecord(id=m.id)
        rec.name = m.name
        rec.default_severity = int(m.severity)
        rec.confidence = int(m.confidence)
        rec.cwe = list(m.cwe)
        rec.owasp = list(m.owasp)
        rec.kind = m.kind
        rec.engine = m.engine
        rec.previous_ids = list(m.previous_ids)
        rec.meta = m.to_dict()
        rec.version = version
        db.session.add(rec)
    db.session.flush()


def _event(issue: Issue, kind: str, from_state: str | None, to_state: str | None, scan_id: uuid.UUID | None,
           user_id: uuid.UUID | None = None, comment: str | None = None) -> None:
    db.session.add(IssueEvent(issue_id=issue.id, kind=kind, from_state=from_state, to_state=to_state,
                              scan_id=scan_id, user_id=user_id, comment=comment))


class _Matcher:
    def __init__(self, issues: list[Issue], previous: dict[str, tuple[str, ...]]) -> None:
        self.unmatched: dict[uuid.UUID, Issue] = {i.id: i for i in issues}
        self.previous = previous
        self.by_fp = {i.fingerprint: i for i in issues}
        self.by_line: dict[tuple, list[Issue]] = defaultdict(list)
        self.by_snippet: dict[tuple, list[Issue]] = defaultdict(list)
        for i in issues:
            self.by_line[(i.rule_id, i.current_path, i.line_hash)].append(i)
            self.by_snippet[(i.rule_id, i.snippet_hash)].append(i)

    def _take(self, candidates: list[Issue]) -> Issue | None:
        for c in candidates:
            if c.id in self.unmatched:
                del self.unmatched[c.id]
                return c
        return None

    def match(self, f: Finding, path: str, l_hash: str, s_hash: str) -> Issue | None:
        # 1. huella exacta
        hit = self.by_fp.get(f.fingerprint)
        if hit is not None and hit.id in self.unmatched:
            return self._take([hit])
        rule_ids = (f.rule_id, *self.previous.get(f.rule_id, ()))
        # 2. regla (o ID anterior) + ruta + hash de línea
        for rid in rule_ids:
            hit = self._take(self.by_line.get((rid, path, l_hash), []))
            if hit:
                return hit
        # 3. regla + ruta + mensaje + línea ±3
        for issue in list(self.unmatched.values()):
            if issue.rule_id in rule_ids and issue.current_path == path and issue.message == f.message \
                    and abs(issue.current_line - f.line) <= 3:
                return self._take([issue])
        # 4. regla + fragmento en otro archivo (renombre)
        for rid in rule_ids:
            hit = self._take([i for i in self.by_snippet.get((rid, s_hash), []) if i.current_path != path])
            if hit:
                return hit
        return None


def previous_scan(scan: Scan) -> Scan | None:
    return db.session.scalars(
        select(Scan).where(Scan.project_id == scan.project_id, Scan.category == scan.category,
                           Scan.status == "done", Scan.id != scan.id)
        .order_by(Scan.finished_at.desc()).limit(1)
    ).first()


def ingest(scan: Scan, report: ScanReport, ruleset: RuleSet, finished_at: datetime | None = None) -> IngestResult:
    """Guarda las ocurrencias del escaneo y actualiza el ciclo de vida de los issues."""
    finished_at = finished_at or utcnow()
    previous = {m.id: m.previous_ids for m in ruleset.metas()}
    known_rules = set(db.session.scalars(select(RuleRecord.id)))
    base = previous_scan(scan)
    scan.baseline_scan_id = base.id if base else None

    issues = list(db.session.scalars(select(Issue).where(Issue.project_id == scan.project_id,
                                                         Issue.category == scan.category)))
    matcher = _Matcher(issues, previous)
    lines_by_path = {p: s.splitlines() for p, s in report.sources.items()}
    result = IngestResult()
    by_severity: dict[str, int] = defaultdict(int)

    for f in report.findings:
        if f.rule_id not in known_rules:
            continue
        path = normalize_path(f.path)
        lines = lines_by_path.get(f.path, [])
        l_hash = line_hash(lines, f.line)
        s_hash = snippet_hash(lines, f)
        issue = matcher.match(f, path, l_hash, s_hash)
        if issue is None:
            issue = Issue(id=uuid.uuid4(), project_id=scan.project_id, rule_id=f.rule_id, category=scan.category,
                          fingerprint=f.fingerprint, fingerprint_version=FP_VERSION, severity=int(f.severity),
                          current_path=path, current_line=f.line, message=f.message, line_hash=l_hash,
                          snippet_hash=s_hash, first_seen_scan_id=scan.id, first_seen_at=finished_at,
                          lifecycle="open")
            db.session.add(issue)
            db.session.flush()
            _event(issue, "lifecycle", None, "open", scan.id)
            change = "new"
        else:
            change = "persisting"
            if issue.lifecycle == "fixed":
                if issue.triage == "false_positive":
                    issue.lifecycle = "open"
                    _event(issue, "lifecycle", "fixed", "open", scan.id)
                else:
                    issue.lifecycle = "reopened"
                    issue.reopened_count += 1
                    issue.fixed_at = None
                    _event(issue, "lifecycle", "fixed", "reopened", scan.id)
                    change = "reopened"
            issue.fingerprint = f.fingerprint
            issue.rule_id = f.rule_id
            issue.current_path, issue.current_line = path, f.line
            issue.message, issue.severity = f.message, int(f.severity)
            issue.line_hash, issue.snippet_hash = l_hash, s_hash
        issue.last_seen_scan_id = scan.id
        setattr(result, change, getattr(result, change) + 1)
        if not f.suppressed and issue.triage != "false_positive":
            by_severity[f.severity.label] += 1
        db.session.add(Occurrence(
            scan_id=scan.id, issue_id=issue.id, path=path, start_line=f.line, end_line=f.end_line,
            start_col=f.col, end_col=f.end_col, message=f.message, severity=int(f.severity),
            confidence=int(f.confidence), snippet=redact(f.snippet, f.rule_id), line_hash=l_hash,
            trace=[t.to_dict() for t in f.trace], variant=f.variant, suppressed=f.suppressed,
            suppression_reason=f.suppression_reason, change=change,
        ))

    # Issues no vistos en este escaneo -> corregidos (si la regla estaba activa y el archivo en alcance)
    enabled = set(scan.rules_enabled or [])
    scanned_paths = {normalize_path(p) for p in report.sources}
    full_scope = scan.source in FULL_SCOPE_SOURCES
    for issue in matcher.unmatched.values():
        if issue.lifecycle == "fixed":
            continue
        if issue.rule_id not in enabled:
            continue
        if not full_scope and issue.current_path not in scanned_paths:
            continue
        old = issue.lifecycle
        issue.lifecycle = "fixed"
        issue.fixed_at = finished_at
        _event(issue, "lifecycle", old, "fixed", scan.id)
        result.fixed += 1

    scan.summary = {
        "by_severity": {k: by_severity.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
        "total": sum(by_severity.values()),
        "suppressed": sum(1 for f in report.findings if f.suppressed),
        "new": result.new, "fixed": result.fixed, "persisting": result.persisting, "reopened": result.reopened,
    }
    db.session.flush()
    return result


def set_triage(issue: Issue, triage: str, justification: str | None, user_id: uuid.UUID) -> None:
    if triage in {"false_positive", "accepted", "wont_fix"} and not (justification or "").strip():
        raise ValueError("justification_required")
    old = issue.triage
    issue.triage = triage
    issue.triage_justification = (justification or "").strip() or None
    _event(issue, "triage", old, triage, None, user_id=user_id, comment=issue.triage_justification)


def add_comment(issue: Issue, body: str, user_id: uuid.UUID) -> None:
    _event(issue, "comment", None, None, None, user_id=user_id, comment=body)
