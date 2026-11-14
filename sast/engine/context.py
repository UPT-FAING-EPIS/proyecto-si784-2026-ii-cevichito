"""`FileContext`: todo lo que las reglas necesitan de un archivo, calculado una vez.

Cada análisis caro (AST, imports, taint) es perezoso (`cached_property`) y se
comparte entre todas las reglas que lo piden. Así se elimina el patrón anterior
en el que cada regla de inyección repetía el análisis completo.
"""

from __future__ import annotations

import ast
import re
from functools import cached_property

from ..taint.analysis import TaintResult, analyze
from ..taint.models import TaintModels, load_models
from .languages import AST_LANGUAGES, comment_prefixes

# `# sast: ignore[py/weak-hash, py/xss] reason: ...`   o   `# sast: ignore`
_SAST_IGNORE = re.compile(r"(?:#|//)\s*sast:\s*ignore(?:\[(?P<ids>[^\]]*)\])?(?:\s*reason:\s*(?P<reason>.*))?", re.I)
# `# nosec`  o  `# nosec B324, B303` (compatibilidad con Bandit)
_NOSEC = re.compile(r"(?:#|//)\s*nosec\b(?P<ids>[\sA-Za-z0-9_,/.-]*)", re.I)

#: Traducción de IDs de Bandit a IDs de SAST Studio para `# nosec Bxxx`.
BANDIT_IDS: dict[str, str] = {
    "B102": "py/dangerous-function", "B307": "py/dangerous-function",
    "B105": "generic/hardcoded-secret", "B106": "generic/hardcoded-secret", "B107": "generic/hardcoded-secret",
    "B201": "py/security-misconfiguration", "B501": "py/security-misconfiguration",
    "B301": "py/insecure-deserialization", "B302": "py/insecure-deserialization",
    "B403": "py/insecure-deserialization", "B506": "py/insecure-deserialization",
    "B303": "py/weak-hash", "B324": "py/weak-hash",
    "B304": "py/weak-cipher", "B305": "py/weak-cipher",
    "B311": "py/insecure-random",
    "B310": "py/ssrf",
    "B602": "py/command-injection", "B605": "py/command-injection",
    "B608": "py/sql-injection",
}


class Suppression:
    __slots__ = ("ids", "reason")

    def __init__(self, ids: frozenset[str] | None, reason: str) -> None:
        self.ids = ids          # None = todas las reglas
        self.reason = reason

    def covers(self, rule_id: str, previous_ids: tuple[str, ...] = ()) -> bool:
        if self.ids is None:
            return True
        return rule_id in self.ids or any(p in self.ids for p in previous_ids)


def _parse_ids(raw: str | None) -> frozenset[str] | None:
    if raw is None:
        return None
    ids = {x.strip() for x in re.split(r"[,\s]+", raw) if x.strip()}
    if not ids:
        return None
    return frozenset(BANDIT_IDS.get(i.upper(), i) for i in ids)


class FileContext:
    """Contexto de análisis de un archivo."""

    def __init__(self, path: str, source: str, language: str, taint_models: TaintModels | None = None) -> None:
        self.path = path
        self.source = source
        self.language = language
        self.taint_models = taint_models or load_models()

    # -- texto ------------------------------------------------------------------
    @cached_property
    def lines(self) -> list[str]:
        return self.source.splitlines()

    def line(self, number: int) -> str:
        if 1 <= number <= len(self.lines):
            return self.lines[number - 1]
        return ""

    def is_comment_line(self, number: int) -> bool:
        text = self.line(number).strip()
        return any(text.startswith(p) for p in comment_prefixes(self.language))

    def snippet(self, line: int, end_line: int | None = None, context: int = 0) -> str:
        start = max(1, line - context)
        end = min(len(self.lines), (end_line or line) + context)
        return "\n".join(self.lines[i - 1] for i in range(start, end + 1))

    # -- AST --------------------------------------------------------------------
    @cached_property
    def tree(self) -> ast.Module | None:
        if self.language not in AST_LANGUAGES:
            return None
        try:
            return ast.parse(self.source, filename=self.path)
        except (SyntaxError, ValueError):
            return None

    @cached_property
    def nodes(self) -> list[ast.AST]:
        """Todos los nodos del AST, recorridos una sola vez y compartidos por todos."""
        return list(ast.walk(self.tree)) if self.tree is not None else []

    @cached_property
    def imports(self) -> dict[str, str]:
        """Alias local -> nombre calificado (`np` -> `numpy`, `system` -> `os.system`)."""
        out: dict[str, str] = {}
        if self.tree is None:
            return out
        for node in self.nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        out[alias.asname] = alias.name
                    else:
                        root = alias.name.split(".")[0]
                        out.setdefault(root, root)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for alias in node.names:
                    out[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        return out

    def qualname(self, node: ast.AST) -> str | None:
        """Nombre calificado de una expresión `a.b.c` o de la función de una llamada."""
        if isinstance(node, ast.Call):
            node = node.func
        key = id(node)
        cache = self.__dict__.setdefault("_qn_cache", {})
        if key in cache:
            return cache[key]
        cache[key] = value = self._qualname(node)
        return value

    def _qualname(self, node: ast.AST) -> str | None:
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Call):
            inner = self.qualname(cur)
            if inner is None:
                return None
            parts.append(inner)
        elif isinstance(cur, ast.Name):
            parts.append(self.imports.get(cur.id, cur.id))
        else:
            return None
        return ".".join(reversed(parts))

    # -- taint ------------------------------------------------------------------
    @cached_property
    def taint(self) -> TaintResult:
        if self.tree is None:
            return TaintResult()
        return analyze(self.tree, self.taint_models, self.qualname, nodes=self.nodes)

    # -- supresiones -----------------------------------------------------------
    @cached_property
    def suppressions(self) -> dict[int, Suppression]:
        out: dict[int, Suppression] = {}
        for number, text in enumerate(self.lines, start=1):
            m = _SAST_IGNORE.search(text)
            if m:
                out[number] = Suppression(_parse_ids(m.group("ids")), (m.group("reason") or "").strip())
                continue
            m = _NOSEC.search(text)
            if m:
                out[number] = Suppression(_parse_ids(m.group("ids")), "nosec")
        return out

    def suppression_for(self, line: int, rule_id: str, previous_ids: tuple[str, ...] = ()) -> Suppression | None:
        """Supresión en la misma línea o en una línea de comentario inmediatamente anterior."""
        s = self.suppressions.get(line)
        if s and s.covers(rule_id, previous_ids):
            return s
        s = self.suppressions.get(line - 1)
        if s and self.is_comment_line(line - 1) and s.covers(rule_id, previous_ids):
            return s
        return None
