"""Exportación a SARIF 2.1.0.

- `ruleId` estable y catálogo de reglas en `tool.driver.rules`.
- `partialFingerprints["sastStudio/v1"]` con la huella `sastfp/v1`.
- `baselineState` (new/unchanged/absent) cuando se pasa la comparación con el
  escaneo anterior.
- `suppressions` para hallazgos suprimidos en el código o por triage.
- `invocations[0].toolExecutionNotifications` con los errores de reglas.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .. import __version__
from ..engine.fingerprint import SARIF_KEY
from ..engine.runner import ScanReport
from ..rules.api import Finding, RuleMeta, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/NestorSnIbz/sast-studio"

_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
          Severity.LOW: "note", Severity.INFO: "note"}


def _rule_descriptor(meta: RuleMeta) -> dict[str, Any]:
    tags = ["security", *meta.cwe, *(f"OWASP-{o}" for o in meta.owasp)]
    if meta.engine == "heuristic":
        tags.append("heuristic")
    help_text = "\n\n".join(x for x in (meta.explanation, meta.remediation) if x)
    desc: dict[str, Any] = {
        "id": meta.id,
        "name": meta.name,
        "shortDescription": {"text": meta.name},
        "fullDescription": {"text": meta.explanation or meta.name},
        "help": {"text": help_text or meta.name,
                 "markdown": f"{help_text}\n\n**Vulnerable**\n```\n{meta.example_bad}\n```\n\n**Corregido**\n```\n{meta.example_good}\n```"},
        "defaultConfiguration": {"level": _LEVEL[meta.severity]},
        "properties": {
            "tags": tags,
            "precision": {3: "high", 2: "medium", 1: "low"}[int(meta.confidence)],
            "problem.severity": _LEVEL[meta.severity],
            "kind": meta.kind,
            "engine": meta.engine,
        },
    }
    if meta.security_severity is not None:
        desc["properties"]["security-severity"] = f"{meta.security_severity:.1f}"
    if meta.references:
        desc["helpUri"] = meta.references[0]
    if meta.previous_ids:
        desc["deprecatedIds"] = list(meta.previous_ids)
    return desc


def _result(f: Finding, rule_index: int, baseline_state: str | None,
            triage: Mapping[str, Mapping[str, str]] | None) -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": f.line, "startColumn": f.col + 1, "endLine": f.end_line,
                              "endColumn": max(f.end_col, f.col) + 1}
    if f.snippet:
        region["snippet"] = {"text": f.snippet}
    res: dict[str, Any] = {
        "ruleId": f.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[f.severity],
        "message": {"text": f.message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                                            "region": region}}],
        "partialFingerprints": {SARIF_KEY: f.fingerprint},
        "properties": {"confidence": f.confidence.label, "severity": f.severity.label},
    }
    if f.variant:
        res["properties"]["variant"] = f.variant
    if f.trace:
        res["codeFlows"] = [{"threadFlows": [{"locations": [
            {"location": {"physicalLocation": {"artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                                               "region": {"startLine": step.line}},
                          "message": {"text": step.description}}}
            for step in f.trace
        ]}]}]
    if baseline_state:
        res["baselineState"] = baseline_state
    suppressions = []
    if f.suppressed:
        suppressions.append({"kind": "inSource", "status": "accepted", "justification": f.suppression_reason or ""})
    t = (triage or {}).get(f.fingerprint)
    if t and t.get("triage") in {"false_positive", "accepted", "wont_fix"}:
        suppressions.append({"kind": "external", "status": "accepted",
                             "justification": f"{t['triage']}: {t.get('justification', '')}".strip()})
    if suppressions:
        res["suppressions"] = suppressions
    return res


def to_sarif(
    report: ScanReport,
    rules: Iterable[RuleMeta],
    *,
    baseline_states: Mapping[str, str] | None = None,
    absent: Iterable[Finding] = (),
    triage: Mapping[str, Mapping[str, str]] | None = None,
    automation_id: str | None = None,
) -> dict[str, Any]:
    metas = sorted(rules, key=lambda m: m.id)
    index = {m.id: i for i, m in enumerate(metas)}
    results = [
        _result(f, index.get(f.rule_id, 0), (baseline_states or {}).get(f.fingerprint) if baseline_states is not None else None, triage)
        for f in report.findings
    ]
    for f in absent:
        results.append(_result(f, index.get(f.rule_id, 0), "absent", triage))
    run: dict[str, Any] = {
        "tool": {"driver": {
            "name": "SAST Studio",
            "semanticVersion": __version__,
            "version": __version__,
            "informationUri": INFORMATION_URI,
            "rules": [_rule_descriptor(m) for m in metas],
        }},
        "invocations": [{
            "executionSuccessful": True,
            "toolExecutionNotifications": [
                {"level": "error", "message": {"text": f"{e.rule_id} falló en {e.path}: {e.exc_type}: {e.message}"},
                 "descriptor": {"id": e.rule_id}}
                for e in report.rule_errors
            ],
        }],
        "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
        "columnKind": "unicodeCodePoints",
        "results": results,
    }
    if automation_id:
        run["automationDetails"] = {"id": automation_id}
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
