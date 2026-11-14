"""Reglas declarativas en YAML (subconjunto de la sintaxis de Semgrep).

Ejemplo mínimo (regla AST sobre llamadas de Python):

    rules:
      - id: py/weak-hash
        name: Hash criptográfico débil
        message: "Se usa {variant}..."
        severity: MEDIUM
        confidence: HIGH
        languages: [python]
        engine: ast
        match:
          call-either:
            - call: "hashlib.$ALG"
            - { call: "hashlib.new", arg0: "$ALG" }
          where:
            - metavar-regex: { $ALG: "(?i)^(md5|sha1)$" }
          not:
            - kwarg: { usedforsecurity: false }
        variant: $ALG

Ejemplo de regla heurística (regex por línea, para lenguajes sin AST):

      - id: multi/xss
        engine: heuristic
        languages: [web]
        regex: ['\\b(?:innerHTML|outerHTML)\\s*=']
        regex-not: ['=\\s*["\\x27]{2}']

El subconjunto está acotado a propósito: `call`, `call-either`, `arg0`,
`where/metavar-regex`, `not/kwarg`, `not/kwarg-regex`, `regex` y `regex-not`.
`variant: $CALL` usa el nombre calificado de la llamada.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Iterable, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .api import Confidence, Finding, LoadError, PythonRule, RuleMeta, Severity

_METAVAR = re.compile(r"\$([A-Z][A-Z0-9_]*)")


# ---------------------------------------------------------------------------
# Esquema (pydantic)
# ---------------------------------------------------------------------------

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class CallPattern(_Strict):
    call: str
    arg0: str | None = None


class MatchSpec(_Strict):
    call: str | None = None
    arg0: str | None = None
    call_either: list[CallPattern] | None = Field(default=None, alias="call-either")
    where: list[dict[str, dict[str, str]]] = Field(default_factory=list)
    not_: list[dict[str, dict[str, Any]]] = Field(default_factory=list, alias="not")

    @model_validator(mode="after")
    def _one_form(self) -> "MatchSpec":
        if bool(self.call) == bool(self.call_either):
            raise ValueError("match requiere exactamente uno de 'call' o 'call-either'")
        for cond in self.where:
            if set(cond) != {"metavar-regex"}:
                raise ValueError(f"condición 'where' no soportada: {sorted(cond)}")
        for cond in self.not_:
            if set(cond) - {"kwarg", "kwarg-regex"} or len(cond) != 1:
                raise ValueError(f"condición 'not' no soportada: {sorted(cond)}")
        return self

    def patterns(self) -> list[CallPattern]:
        if self.call_either:
            return self.call_either
        return [CallPattern(call=self.call or "", arg0=self.arg0)]


class Metadata(_Strict):
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    security_severity: float | None = None
    references: list[str] = Field(default_factory=list)


class Docs(_Strict):
    explanation: str
    remediation: str
    example_bad: str
    example_good: str


class RuleSpec(_Strict):
    id: str
    name: str
    message: str
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    languages: list[str]
    engine: Literal["ast", "heuristic"]
    kind: Literal["problem", "path-problem"] = "problem"
    metadata: Metadata = Field(default_factory=Metadata)
    docs: Docs
    previous_ids: list[str] = Field(default_factory=list)
    supersedes: list[str] = Field(default_factory=list)
    match: MatchSpec | None = None
    regex: list[str] | None = None
    regex_not: list[str] = Field(default_factory=list, alias="regex-not")
    variant: str | None = None

    @field_validator("regex", "regex_not")
    @classmethod
    def _compiles(cls, value: list[str] | None) -> list[str] | None:
        for pattern in value or []:
            re.compile(pattern)
        return value

    @model_validator(mode="after")
    def _engine_fields(self) -> "RuleSpec":
        if self.engine == "ast" and self.match is None:
            raise ValueError(f"{self.id}: engine 'ast' requiere 'match'")
        if self.engine == "heuristic" and not self.regex:
            raise ValueError(f"{self.id}: engine 'heuristic' requiere 'regex'")
        return self

    def to_meta(self) -> RuleMeta:
        return RuleMeta(
            id=self.id,
            name=self.name,
            message=self.message,
            severity=Severity.parse(self.severity),
            confidence=Confidence.parse(self.confidence),
            languages=tuple(self.languages),
            cwe=tuple(self.metadata.cwe),
            owasp=tuple(self.metadata.owasp),
            kind=self.kind,
            engine=self.engine,
            security_severity=self.metadata.security_severity,
            previous_ids=tuple(self.previous_ids),
            supersedes=tuple(self.supersedes),
            references=tuple(self.metadata.references),
            explanation=self.docs.explanation.strip(),
            remediation=self.docs.remediation.strip(),
            example_bad=self.docs.example_bad.rstrip(),
            example_good=self.docs.example_good.rstrip(),
        )


class RuleFile(_Strict):
    rules: list[RuleSpec]


# ---------------------------------------------------------------------------
# Compilación a reglas ejecutables
# ---------------------------------------------------------------------------

def _pattern_to_regex(pattern: str) -> re.Pattern[str]:
    out = []
    pos = 0
    for m in _METAVAR.finditer(pattern):
        out.append(re.escape(pattern[pos:m.start()]).replace(r"\*", ".*"))
        out.append(f"(?P<{m.group(1)}>[A-Za-z_][A-Za-z0-9_]*)")
        pos = m.end()
    out.append(re.escape(pattern[pos:]).replace(r"\*", ".*"))
    return re.compile("^" + "".join(out) + "$")


class DeclarativeAstRule(PythonRule):
    node_types = (ast.Call,)

    def __init__(self, spec: RuleSpec) -> None:
        self.meta = spec.to_meta()
        self._spec = spec
        assert spec.match is not None
        self._patterns = [(_pattern_to_regex(p.call), p.arg0) for p in spec.match.patterns()]
        self._where = [
            (name.lstrip("$"), re.compile(regex))
            for cond in spec.match.where
            for name, regex in cond["metavar-regex"].items()
        ]
        self._not = spec.match.not_

    def _bindings(self, ctx, call: ast.Call) -> Iterable[dict[str, str]]:
        """Todas las formas en que la llamada encaja con algún patrón (en orden)."""
        qn = ctx.qualname(call)
        if not qn:
            return
        for regex, arg0 in self._patterns:
            m = regex.match(qn)
            if not m:
                continue
            binds = {k: v for k, v in m.groupdict().items() if v is not None}
            if arg0 is not None:
                if not call.args or not isinstance(call.args[0], ast.Constant) or not isinstance(call.args[0].value, str):
                    continue
                value = call.args[0].value
                mv = _METAVAR.fullmatch(arg0)
                if mv:
                    binds[mv.group(1)] = value
                elif value != arg0:
                    continue
            yield binds

    def _where_ok(self, binds: dict[str, str]) -> bool:
        # Una condición solo se evalúa si el patrón que encajó liga esa metavariable.
        return all(regex.search(binds[name]) for name, regex in self._where if name in binds)

    def _excluded(self, call: ast.Call) -> bool:
        for cond in self._not:
            for kind, spec in cond.items():
                for name, expected in spec.items():
                    for kw in call.keywords:
                        if kw.arg != name:
                            continue
                        if kind == "kwarg" and isinstance(kw.value, ast.Constant) and kw.value.value == expected:
                            return True
                        if kind == "kwarg-regex" and re.search(str(expected), ast.unparse(kw.value)):
                            return True
        return False

    def check(self, ctx, node) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        binds = next((b for b in self._bindings(ctx, node) if self._where_ok(b)), None)
        if binds is None or self._excluded(node):
            return
        variant = None
        if self._spec.variant == "$CALL":
            variant = ctx.qualname(node)
        elif self._spec.variant:
            mv = _METAVAR.fullmatch(self._spec.variant)
            variant = binds.get(mv.group(1), "").lower() if mv else self._spec.variant
        yield self.finding(ctx, node, variant=variant)


class DeclarativeRegexRule(PythonRule):
    node_types = ()

    def __init__(self, spec: RuleSpec) -> None:
        self.meta = spec.to_meta()
        self._regex = [re.compile(p) for p in spec.regex or []]
        self._regex_not = [re.compile(p) for p in spec.regex_not]
        self._variant = spec.variant

    def check(self, ctx, node) -> Iterable[Finding]:
        for number, text in enumerate(ctx.lines, start=1):
            if ctx.is_comment_line(number):
                continue
            if any(r.search(text) for r in self._regex_not):
                continue
            for regex in self._regex:
                m = regex.search(text)
                if m:
                    yield self.finding(ctx, line=number, col=m.start(), end_col=m.end(), variant=self._variant)
                    break


def compile_spec(spec: RuleSpec) -> PythonRule:
    if spec.engine == "ast":
        return DeclarativeAstRule(spec)
    return DeclarativeRegexRule(spec)


def load_yaml_file(path: Path) -> tuple[list[PythonRule], list[LoadError]]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        parsed = RuleFile.model_validate(data)
    except Exception as exc:  # validación o YAML inválido
        return [], [LoadError(str(path), f"{type(exc).__name__}: {exc}")]
    return [compile_spec(s) for s in parsed.rules], []


def load_yaml_dir(directory: Path) -> tuple[list[PythonRule], list[LoadError]]:
    rules: list[PythonRule] = []
    errors: list[LoadError] = []
    for path in sorted(directory.rglob("*.y*ml")):
        r, e = load_yaml_file(path)
        rules.extend(r)
        errors.extend(e)
    return rules, errors
