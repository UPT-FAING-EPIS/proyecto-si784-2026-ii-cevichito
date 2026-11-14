"""Pruebas de reglas basadas en anotaciones (compartido por pytest y `sast test-rules`).

Convención, al estilo `semgrep --test` (la anotación va en la línea anterior):

    # ruleid: <id>      la línea siguiente DEBE producir <id>
    # ok: <id>          la línea siguiente NO debe producir <id>
    # todoruleid: <id>  falso negativo conocido (no hace fallar)
    # todook: <id>      falso positivo conocido (no hace fallar)

En JS/PHP se usa `//` en lugar de `#`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

_ANNOTATION = re.compile(r"^\s*(?:#|//)\s*(ruleid|ok|todoruleid|todook)\s*:\s*([\w./-]+)\s*$")


@dataclass
class Expectations:
    must: set[tuple[str, int]] = field(default_factory=set)
    must_not: set[tuple[str, int]] = field(default_factory=set)
    todo_must: set[tuple[str, int]] = field(default_factory=set)
    todo_must_not: set[tuple[str, int]] = field(default_factory=set)

    @property
    def rule_ids(self) -> set[str]:
        return {rid for rid, _ in self.must | self.must_not | self.todo_must | self.todo_must_not}


@dataclass
class CaseResult:
    path: Path
    missing: list[tuple[str, int]]
    unexpected: list[tuple[str, int]]

    @property
    def ok(self) -> bool:
        return not self.missing and not self.unexpected


def parse_expectations(path: Path) -> Expectations:
    exp = Expectations()
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        m = _ANNOTATION.match(line)
        if not m:
            continue
        kind, rule_id = m.groups()
        bucket = {"ruleid": exp.must, "ok": exp.must_not, "todoruleid": exp.todo_must, "todook": exp.todo_must_not}[kind]
        bucket.add((rule_id, idx + 2))
    return exp


def case_files(directory: Path) -> list[Path]:
    return sorted(p for p in Path(directory).iterdir() if p.is_file() and not p.name.startswith("."))


def default_findings(path: Path) -> list[tuple[str, int]]:
    from .engine.runner import Engine

    report = Engine().scan_source(path.read_text(encoding="utf-8"), path.name)
    return [(f.rule_id, f.line) for f in report.findings if not f.suppressed]


def run_case(path: Path, findings: Callable[[Path], list[tuple[str, int]]] = default_findings) -> CaseResult:
    exp = parse_expectations(path)
    got = {pair for pair in findings(path) if pair[0] in exp.rule_ids}
    return CaseResult(path, sorted(exp.must - got), sorted(exp.must_not & got))


def covered_rule_ids(directory: Path) -> set[str]:
    out: set[str] = set()
    for case in case_files(directory):
        exp = parse_expectations(case)
        out |= {rid for rid, _ in exp.must}
    return out
