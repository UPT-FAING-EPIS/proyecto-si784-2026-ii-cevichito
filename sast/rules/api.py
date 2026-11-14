"""Contrato público de las reglas: metadatos, hallazgos y errores.

Toda regla (Python o YAML) implementa el protocolo `Rule`. Los metadatos son
inmutables: el `id` no cambia por sub-patrón; el sub-patrón va en `variant`.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, replace
from enum import IntEnum
from typing import TYPE_CHECKING, Any, ClassVar, Iterable, Protocol, runtime_checkable

if TYPE_CHECKING:  # pragma: no cover
    from ..engine.context import FileContext


class Severity(IntEnum):
    """Severidad ordenable. Los valores coinciden con las bandas de `security_severity`."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: "str | int | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]

    @property
    def label(self) -> str:
        return self.name.lower()

    @property
    def label_es(self) -> str:
        return {0: "informativa", 1: "baja", 2: "media", 3: "alta", 4: "crítica"}[int(self)]


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, value: "str | int | Confidence") -> "Confidence":
        if isinstance(value, Confidence):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class RuleMeta:
    """Metadatos inmutables de una regla."""

    id: str                                  # "py/weak-hash": prefijo de lenguaje + sustantivo
    name: str                                # nombre corto en español
    message: str                             # admite {variant}, {source}, {sink}
    severity: Severity
    confidence: Confidence
    languages: tuple[str, ...]
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    kind: str = "problem"                    # "problem" | "path-problem" (taint)
    engine: str = "ast"                      # "ast" | "taint" | "heuristic" (regex)
    security_severity: float | None = None   # 0-10, bandas CVSS
    previous_ids: tuple[str, ...] = ()       # IDs anteriores (renombres, baseline)
    supersedes: tuple[str, ...] = ()         # oculta otra regla en el mismo span
    references: tuple[str, ...] = ()
    # Panel didáctico (RF-24)
    explanation: str = ""                    # qué es y por qué es peligroso
    remediation: str = ""                    # cómo corregirlo
    example_bad: str = ""
    example_good: str = ""

    def __post_init__(self) -> None:
        if "/" not in self.id:
            raise ValueError(f"ID de regla inválido {self.id!r}: debe tener la forma 'lenguaje/nombre'")
        if self.kind not in {"problem", "path-problem"}:
            raise ValueError(f"{self.id}: kind inválido {self.kind!r}")
        if self.engine not in {"ast", "taint", "heuristic"}:
            raise ValueError(f"{self.id}: engine inválido {self.engine!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "message": self.message,
            "severity": self.severity.label,
            "confidence": self.confidence.label,
            "languages": list(self.languages),
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "kind": self.kind,
            "engine": self.engine,
            "security_severity": self.security_severity,
            "previous_ids": list(self.previous_ids),
            "supersedes": list(self.supersedes),
            "references": list(self.references),
            "explanation": self.explanation,
            "remediation": self.remediation,
            "example_bad": self.example_bad,
            "example_good": self.example_good,
        }


@dataclass(frozen=True)
class TraceStep:
    line: int
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {"line": self.line, "description": self.description}


@dataclass(frozen=True, order=False)
class Finding:
    rule_id: str
    path: str                     # relativo a la raíz del escaneo, con "/"
    line: int
    col: int
    end_line: int
    end_col: int
    message: str
    severity: Severity
    confidence: Confidence
    trace: tuple[TraceStep, ...] = ()
    variant: str | None = None
    suppressed: bool = False
    suppression_reason: str | None = None
    snippet: str = ""
    fingerprint: str = ""

    @property
    def span(self) -> tuple[str, int, int, int, int]:
        return (self.path, self.line, self.col, self.end_line, self.end_col)

    def sort_key(self) -> tuple:
        return (self.path, self.line, self.col, self.rule_id)

    def with_(self, **changes: Any) -> "Finding":
        return replace(self, **changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "path": self.path,
            "line": self.line,
            "col": self.col,
            "end_line": self.end_line,
            "end_col": self.end_col,
            "message": self.message,
            "severity": self.severity.label,
            "confidence": self.confidence.label,
            "trace": [t.to_dict() for t in self.trace],
            "variant": self.variant,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "snippet": self.snippet,
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class RuleError:
    """Fallo de una regla en un archivo. El traceback completo va solo al log."""

    rule_id: str
    path: str
    exc_type: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "path": self.path, "exc_type": self.exc_type, "message": self.message}


@runtime_checkable
class Rule(Protocol):
    meta: RuleMeta
    node_types: tuple[type[ast.AST], ...]   # () = regla de archivo completo

    def check(self, ctx: "FileContext", node: ast.AST | None) -> Iterable[Finding]: ...


class PythonRule:
    """Base práctica para reglas escritas en Python.

    Las subclases definen `meta`, opcionalmente `node_types`, e implementan
    `check`. `finding()` construye el hallazgo con el ID estable de la regla.
    """

    meta: ClassVar[RuleMeta]
    node_types: ClassVar[tuple[type[ast.AST], ...]] = ()

    def check(self, ctx: "FileContext", node: ast.AST | None) -> Iterable[Finding]:  # pragma: no cover
        raise NotImplementedError

    def finding(
        self,
        ctx: "FileContext",
        node: ast.AST | None = None,
        *,
        line: int | None = None,
        col: int = 0,
        end_line: int | None = None,
        end_col: int | None = None,
        message: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        trace: Iterable[TraceStep] = (),
        variant: str | None = None,
        **fmt: str,
    ) -> Finding:
        if node is not None:
            line = getattr(node, "lineno", line or 1)
            col = getattr(node, "col_offset", col)
            end_line = getattr(node, "end_lineno", None) or line
            end_col = getattr(node, "end_col_offset", None) or col
        line = line or 1
        end_line = end_line or line
        end_col = end_col if end_col is not None else col
        text = message if message is not None else self.meta.message
        try:
            text = text.format(variant=variant or "", **fmt)
        except (KeyError, IndexError):
            pass
        return Finding(
            rule_id=self.meta.id,
            path=ctx.path,
            line=line,
            col=col,
            end_line=end_line,
            end_col=end_col,
            message=text,
            severity=severity if severity is not None else self.meta.severity,
            confidence=confidence if confidence is not None else self.meta.confidence,
            trace=tuple(trace),
            variant=variant,
        )


@dataclass
class LoadError:
    source: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "message": self.message}


__all__ = [
    "Severity",
    "Confidence",
    "RuleMeta",
    "TraceStep",
    "Finding",
    "RuleError",
    "Rule",
    "PythonRule",
    "LoadError",
]
