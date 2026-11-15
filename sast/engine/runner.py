"""Runner del motor: recorre archivos, ejecuta reglas y post-procesa hallazgos.

Por archivo:
  1. Construye un `FileContext` (AST, imports y taint se calculan una vez).
  2. Agrupa las reglas por tipo de nodo y recorre el AST una sola vez.
  3. Ejecuta cada regla en su propio try/except y acumula `RuleError`.
  4. Ejecuta las reglas de archivo completo (regex/heurísticas).
  5. Marca supresiones (no borra), deduplica por span, aplica `supersedes`,
     calcula la huella y ordena.
"""

from __future__ import annotations

import ast
import fnmatch
import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .. import __version__
from ..rules.api import Confidence, Finding, Rule, RuleError, Severity
from ..rules.registry import RuleSet, default_ruleset
from .context import FileContext
from .fingerprint import assign_fingerprints
from .languages import detect_language, language_matches

log = logging.getLogger("sast.engine")

DEFAULT_EXCLUDED_DIRS = (
    "__pycache__", ".git", ".svn", ".hg", "venv", "env", ".venv", "node_modules", "dist", "build",
    ".tox", ".eggs", ".pytest_cache", ".mypy_cache", ".next", "coverage", "site-packages",
    "bower_components", "jspm_packages", "vendor", "third_party",
)
DEFAULT_EXCLUDED_FILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock")
# Código de terceros empaquetado o minificado: no es del usuario y solo mete ruido.
MINIFIED_GLOBS = ("*.min.js", "*-min.js", "*.min.mjs", "*.bundle.js", "*.chunk.js", "*.packed.js")
MINIFIED_AVG_LINE = 250        # media de caracteres por línea a partir de la que se considera minificado
MINIFIED_MIN_BYTES = 2000      # un fragmento corto pegado nunca se descarta por esto


def is_third_party(path: str, source: str | None = None) -> bool:
    """Dependencias, artefactos y archivos minificados: se omiten en cualquier origen (CLI, ZIP, GitHub)."""
    parts = path.replace("\\", "/").split("/")
    name = parts[-1]
    if any(p in DEFAULT_EXCLUDED_DIRS or p.endswith(".egg-info") for p in parts[:-1]):
        return True
    if name in DEFAULT_EXCLUDED_FILES or any(fnmatch.fnmatch(name.lower(), g) for g in MINIFIED_GLOBS):
        return True
    if source is not None and len(source) >= MINIFIED_MIN_BYTES:
        lines = source.count("\n") + 1
        if len(source) / lines > MINIFIED_AVG_LINE:
            return True
    return False
TEST_DIRS = frozenset({"tests", "test", "__tests__", "spec", "specs"})
TEST_GLOBS = ("test_*.py", "*_test.py", "tests/*", "*/tests/*", "*.spec.ts", "*.test.ts", "*.spec.js", "*.test.js")



def is_test_path(rel: str) -> bool:
    """Archivo de pruebas por su carpeta (tests/, spec/…) o por su nombre (test_*.py, *.spec.ts…)."""
    if TEST_DIRS.intersection(rel.split("/")[:-1]):
        return True
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(name, g) for g in TEST_GLOBS)


ProgressFn = Callable[[int, int], None]
CancelFn = Callable[[], bool]


class ScanCanceled(Exception):
    """El escaneo se canceló de forma cooperativa entre archivos."""


@dataclass
class EngineConfig:
    min_confidence: Confidence = Confidence.LOW
    min_severity: Severity = Severity.INFO
    exclude_tests: bool = True
    exclude_globs: tuple[str, ...] = ()
    excluded_dirs: tuple[str, ...] = DEFAULT_EXCLUDED_DIRS
    max_file_bytes: int = 1024 * 1024
    include_suppressed: bool = True


@dataclass
class ScanReport:
    target: str
    findings: list[Finding] = field(default_factory=list)
    rule_errors: list[RuleError] = field(default_factory=list)
    file_errors: list[dict] = field(default_factory=list)
    files_scanned: int = 0
    loc_total: int = 0
    rules_enabled: list[str] = field(default_factory=list)
    engine_version: str = __version__
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    duration_ms: int = 0
    sources: dict[str, str] = field(default_factory=dict)
    partial: bool = False          # se alcanzó el tiempo límite: solo están los archivos analizados
    files_total: int = 0           # archivos que había que analizar (tras las exclusiones)

    def prune_sources(self) -> None:
        """Deja el código solo de los archivos con hallazgos; del resto, solo la ruta.

        La ruta basta para saber qué archivos se analizaron (y así marcar issues como
        corregidos); el código solo hace falta para las huellas y el contexto de cada hallazgo.
        """
        with_findings = {f.path for f in self.findings}
        self.sources = {p: (s if p in with_findings else "") for p, s in self.sources.items()}

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    @property
    def summary(self) -> dict[str, int]:
        counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.active_findings:
            counts[f.severity.label] += 1
        counts["total"] = sum(counts.values())
        counts["suppressed"] = sum(1 for f in self.findings if f.suppressed)
        return counts

    def to_dict(self, include_sources: bool = False) -> dict:
        data = {
            "target": self.target,
            "engine_version": self.engine_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "files_scanned": self.files_scanned,
            "loc_total": self.loc_total,
            "rules_enabled": self.rules_enabled,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "rule_errors": [e.to_dict() for e in self.rule_errors],
            "file_errors": self.file_errors,
            "partial": self.partial,
            "files_total": self.files_total,
        }
        if include_sources:
            data["sources"] = self.sources
        return data


class Engine:
    """Motor de análisis. Se construye uno por escaneo (no comparte estado mutable)."""

    def __init__(self, ruleset: RuleSet | None = None, config: EngineConfig | None = None) -> None:
        self.ruleset = ruleset if ruleset is not None else default_ruleset()
        self.config = config or EngineConfig()
        self._supersedes = {r.meta.id: set(r.meta.supersedes) for r in self.ruleset}
        self._previous = {r.meta.id: r.meta.previous_ids for r in self.ruleset}

    # -- API pública -------------------------------------------------------------
    def scan_source(self, source: str, path: str = "snippet.py") -> ScanReport:
        return self.scan_files([(path, source)], target=path, apply_excludes=False)

    def scan_path(self, target: str | os.PathLike, *, progress: ProgressFn | None = None,
                  should_cancel: CancelFn | None = None) -> ScanReport:
        root = Path(target)
        if root.is_file():
            files = [(root.name, root)]
        else:
            files = [(rel, root / rel) for rel in self.collect(root)]
        loaded: list[tuple[str, str]] = []
        report_errors: list[dict] = []
        for rel, full in files:
            try:
                if full.stat().st_size > self.config.max_file_bytes:
                    report_errors.append({"path": rel, "error": "archivo demasiado grande; omitido"})
                    continue
                loaded.append((rel, full.read_text(encoding="utf-8", errors="replace")))
            except OSError as exc:
                report_errors.append({"path": rel, "error": type(exc).__name__})
        # Un archivo nombrado explícitamente se analiza aunque parezca de pruebas.
        report = self.scan_files(loaded, target=str(target), progress=progress, should_cancel=should_cancel,
                                 apply_excludes=not root.is_file())
        report.file_errors = report_errors + report.file_errors
        return report

    def scan_files(self, files: Iterable[tuple[str, str]], *, target: str = "<memoria>",
                   progress: ProgressFn | None = None, should_cancel: CancelFn | None = None,
                   apply_excludes: bool = True, deadline: float | None = None) -> ScanReport:
        """Analiza archivos ya leídos. Con `apply_excludes` (por defecto) aplica las mismas
        exclusiones que `collect()`: pruebas (si `exclude_tests`), `exclude_globs` y terceros.

        `deadline` (en `time.monotonic()`): al alcanzarlo se deja de analizar y se devuelve lo
        hecho hasta entonces con `partial=True`, en vez de perderlo todo.
        """
        t0 = time.perf_counter()
        files = [(p.replace("\\", "/"), s) for p, s in files if detect_language(p)]
        kept = files if not apply_excludes else [
            (p, s) for p, s in files if not is_third_party(p, s) and not self._excluded(p)]
        if len(kept) != len(files):
            log.info("omitidos %d archivos de terceros o minificados", len(files) - len(kept))
        files = kept
        report = ScanReport(target=target, rules_enabled=self.ruleset.ids, files_total=len(files))
        sources_lines: dict[str, list[str]] = {}
        for index, (path, source) in enumerate(files):
            if should_cancel is not None and should_cancel():
                raise ScanCanceled()
            if deadline is not None and time.monotonic() > deadline:
                report.partial = True
                log.info("tiempo agotado: %d de %d archivos analizados", report.files_scanned, len(files))
                break
            if len(source.encode("utf-8", errors="replace")) > self.config.max_file_bytes:
                report.file_errors.append({"path": path, "error": "archivo demasiado grande; omitido"})
                continue
            ctx = self._context(path, source)
            findings, errors = self.analyze(ctx)
            report.findings.extend(findings)
            report.rule_errors.extend(errors)
            report.files_scanned += 1
            report.loc_total += len(ctx.lines)
            report.sources[path] = source
            sources_lines[path] = ctx.lines
            if progress is not None:
                progress(index + 1, len(files))
        report.findings = [
            f for f in assign_fingerprints(report.findings, sources_lines)
            if f.confidence >= self.config.min_confidence and f.severity >= self.config.min_severity
            and (self.config.include_suppressed or not f.suppressed)
        ]
        report.findings.sort(key=lambda f: f.sort_key())
        report.finished_at = datetime.now(timezone.utc).isoformat()
        report.duration_ms = int((time.perf_counter() - t0) * 1000)
        return report

    # -- recolección de archivos -------------------------------------------------
    def collect(self, root: Path) -> list[str]:
        out: list[str] = []
        excluded = set(self.config.excluded_dirs)
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in excluded and not d.endswith(".egg-info"))
            for name in sorted(filenames):
                rel = Path(dirpath, name).relative_to(root).as_posix()
                if not detect_language(name) or is_third_party(rel):
                    continue
                if self._excluded(rel):
                    continue
                out.append(rel)
        return out

    def _excluded(self, rel: str) -> bool:
        if self.config.exclude_tests and is_test_path(rel):
            return True
        globs = self.config.exclude_globs
        name = rel.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(name, g) for g in globs)

    # -- análisis de un archivo -----------------------------------------------------
    def _context(self, path: str, source: str) -> FileContext:
        return FileContext(path, source, detect_language(path) or "unknown")

    def analyze(self, ctx: FileContext) -> tuple[list[Finding], list[RuleError]]:
        rules = [r for r in self.ruleset if language_matches(ctx.language, r.meta.languages)]
        findings: list[Finding] = []
        errors: list[RuleError] = []
        broken: set[str] = set()

        def run(rule: Rule, node: ast.AST | None) -> None:
            if rule.meta.id in broken:
                return
            try:
                findings.extend(rule.check(ctx, node))
            except Exception as exc:  # una regla rota no oculta a las demás
                broken.add(rule.meta.id)
                errors.append(RuleError(rule.meta.id, ctx.path, type(exc).__name__, str(exc)[:500]))
                log.warning("regla %s falló en %s", rule.meta.id, ctx.path, exc_info=True)

        by_type: dict[type, list[Rule]] = defaultdict(list)
        whole_file: list[Rule] = []
        for r in rules:
            if r.node_types:
                for t in r.node_types:
                    by_type[t].append(r)
            else:
                whole_file.append(r)

        if ctx.tree is not None and by_type:
            for node in ctx.nodes:
                for rule in by_type.get(type(node), ()):
                    run(rule, node)
        for rule in whole_file:
            run(rule, None)

        findings = [self._decorate(ctx, f) for f in findings]
        findings = self._dedupe(findings)
        findings = self._apply_supersedes(findings)
        return findings, errors

    def _decorate(self, ctx: FileContext, f: Finding) -> Finding:
        snippet = ctx.snippet(f.line, min(f.end_line, f.line + 2))
        sup = ctx.suppression_for(f.line, f.rule_id, self._previous.get(f.rule_id, ()))
        if sup is not None:
            return f.with_(snippet=snippet, suppressed=True, suppression_reason=sup.reason or "suprimido en el código")
        return f.with_(snippet=snippet)

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        best: dict[tuple, Finding] = {}
        for f in findings:
            key = (f.rule_id, *f.span)
            cur = best.get(key)
            if cur is None or (f.confidence, f.severity, len(f.trace)) > (cur.confidence, cur.severity, len(cur.trace)):
                best[key] = f
        return list(best.values())

    def _apply_supersedes(self, findings: list[Finding]) -> list[Finding]:
        hidden: set[tuple[str, str, int]] = set()
        for f in findings:
            for other in self._supersedes.get(f.rule_id, ()):
                for line in range(f.line, f.end_line + 1):
                    hidden.add((other, f.path, line))
        return [f for f in findings if (f.rule_id, f.path, f.line) not in hidden]
