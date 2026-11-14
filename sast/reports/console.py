"""Salida de consola legible (con colores ANSI opcionales)."""

from __future__ import annotations

from typing import Iterable

from ..engine.runner import ScanReport
from ..rules.api import RuleMeta, Severity

_COLORS = {Severity.CRITICAL: "\033[91m", Severity.HIGH: "\033[38;5;208m", Severity.MEDIUM: "\033[93m",
           Severity.LOW: "\033[92m", Severity.INFO: "\033[94m"}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def render_console(report: ScanReport, rules: Iterable[RuleMeta], *, color: bool = True, verbose: bool = False) -> str:
    metas = {m.id: m for m in rules}

    def c(sev: Severity, text: str) -> str:
        return f"{_COLORS[sev]}{text}{_RESET}" if color else text

    def b(text: str) -> str:
        return f"{_BOLD}{text}{_RESET}" if color else text

    def d(text: str) -> str:
        return f"{_DIM}{text}{_RESET}" if color else text

    out = [b("SAST Studio") + f"  v{report.engine_version}", f"Objetivo: {report.target}",
           f"Archivos: {report.files_scanned}  ·  Líneas: {report.loc_total}  ·  Duración: {report.duration_ms} ms", ""]
    active = report.active_findings
    for f in active:
        meta = metas.get(f.rule_id)
        name = meta.name if meta else f.rule_id
        heur = " [heurística]" if meta and meta.engine == "heuristic" else ""
        out.append(f"{c(f.severity, f.severity.label_es.upper()):<20} {b(name)}{heur}  {d(f.rule_id)}")
        out.append(f"    {f.path}:{f.line}:{f.col + 1}  (confianza {f.confidence.label})")
        out.append(f"    {f.message}")
        if f.snippet:
            for line in f.snippet.splitlines()[:3]:
                out.append(d(f"    │ {line.rstrip()}"))
        if verbose and f.trace:
            out.append("    Traza:")
            for i, step in enumerate(f.trace, 1):
                out.append(f"      {i}. línea {step.line}: {step.description}")
        if verbose and meta and meta.remediation:
            out.append(f"    Cómo corregirlo: {meta.remediation}")
        out.append("")
    s = report.summary
    out.append(b("Resumen"))
    out.append("  " + "  ·  ".join(f"{Severity.parse(k).label_es}: {s[k]}" for k in ("critical", "high", "medium", "low", "info")))
    out.append(f"  Total: {s['total']}  ·  Suprimidos: {s['suppressed']}")
    if report.rule_errors:
        out.append("")
        out.append(b(f"Errores de reglas ({len(report.rule_errors)})"))
        for e in report.rule_errors:
            out.append(f"  {e.rule_id} en {e.path}: {e.exc_type}: {e.message}")
    if not active:
        out.append("")
        out.append("No se encontraron hallazgos activos.")
    return "\n".join(out) + "\n"
