"""Registro de reglas: integradas (Python), declarativas (YAML) y plugins.

- `@register` añade una clase de regla integrada (falla si el ID se repite).
- `load_yaml_dir()` compila archivos YAML a reglas con el mismo protocolo.
- `load_plugins()` recorre el entry point `sast_studio.rules` de paquetes
  instalados; un plugin roto se anota en `load_errors` sin abortar.

El `RuleSet` resultante es inmutable: cada escaneo construye su propio
`Engine(ruleset, config)` y nunca se comparte estado mutable entre peticiones.
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.metadata import entry_points
from pathlib import Path
from typing import Iterable

from .api import Confidence, LoadError, Rule, RuleMeta, Severity
from .yaml_rules import load_yaml_dir

ENTRY_POINT_GROUP = "sast_studio.rules"
BUILTIN_YAML_DIR = Path(__file__).with_name("yaml")

_BUILTIN_CLASSES: dict[str, type] = {}


def register(cls: type) -> type:
    """Decorador para reglas integradas escritas en Python."""
    meta: RuleMeta = getattr(cls, "meta", None)  # type: ignore[assignment]
    if not isinstance(meta, RuleMeta):
        raise TypeError(f"{cls.__name__} no define 'meta: RuleMeta'")
    existing = _BUILTIN_CLASSES.get(meta.id)
    if existing is not None and existing is not cls:
        raise ValueError(f"ID de regla duplicado: {meta.id}")
    _BUILTIN_CLASSES[meta.id] = cls
    return cls


@dataclass(frozen=True)
class RuleSet:
    rules: tuple[Rule, ...]
    load_errors: tuple[LoadError, ...] = field(default=())

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for r in self.rules:
            if r.meta.id in seen:
                raise ValueError(f"ID de regla duplicado: {r.meta.id}")
            seen.add(r.meta.id)

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    @property
    def ids(self) -> list[str]:
        return [r.meta.id for r in self.rules]

    def get(self, rule_id: str) -> Rule | None:
        for r in self.rules:
            if r.meta.id == rule_id or rule_id in r.meta.previous_ids:
                return r
        return None

    def metas(self) -> list[RuleMeta]:
        return [r.meta for r in self.rules]

    def select(
        self,
        ids: Iterable[str] | None = None,
        languages: Iterable[str] | None = None,
        min_confidence: Confidence | None = None,
        min_severity: Severity | None = None,
    ) -> "RuleSet":
        id_set = set(ids) if ids is not None else None
        lang_set = set(languages) if languages is not None else None
        chosen = []
        for r in self.rules:
            m = r.meta
            if id_set is not None and m.id not in id_set and not id_set.intersection(m.previous_ids):
                continue
            if lang_set is not None and not lang_set.intersection(m.languages):
                continue
            if min_confidence is not None and m.confidence < min_confidence:
                continue
            if min_severity is not None and m.severity < min_severity:
                continue
            chosen.append(r)
        return RuleSet(tuple(chosen), self.load_errors)


def load_builtin() -> list[Rule]:
    from . import builtin  # noqa: F401  (paquete con las reglas Python)

    for mod in pkgutil.iter_modules(builtin.__path__):
        importlib.import_module(f"{builtin.__name__}.{mod.name}")
    return [cls() for _, cls in sorted(_BUILTIN_CLASSES.items())]


def load_plugins() -> tuple[list[Rule], list[LoadError]]:
    rules: list[Rule] = []
    errors: list[LoadError] = []
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            obj = ep.load()
            produced = obj() if callable(obj) and not isinstance(obj, type) else obj
            if isinstance(produced, type):
                produced = [produced()]
            elif not isinstance(produced, (list, tuple)):
                produced = [produced]
            for r in produced:
                if not isinstance(getattr(r, "meta", None), RuleMeta):
                    raise TypeError(f"{r!r} no implementa el protocolo Rule")
                rules.append(r)
        except Exception as exc:
            errors.append(LoadError(f"plugin:{ep.name}", f"{type(exc).__name__}: {exc}"))
    return rules, errors


def build_ruleset(extra_yaml_dirs: Iterable[Path] = (), plugins: bool = True) -> RuleSet:
    rules: list[Rule] = list(load_builtin())
    errors: list[LoadError] = []
    for directory in [BUILTIN_YAML_DIR, *extra_yaml_dirs]:
        r, e = load_yaml_dir(Path(directory))
        rules.extend(r)
        errors.extend(e)
    if plugins:
        r, e = load_plugins()
        known = {x.meta.id for x in rules}
        for rule in r:
            if rule.meta.id in known:
                errors.append(LoadError(f"plugin:{rule.meta.id}", "ID duplicado; se ignora la regla del plugin"))
                continue
            known.add(rule.meta.id)
            rules.append(rule)
    rules.sort(key=lambda x: x.meta.id)
    return RuleSet(tuple(rules), tuple(errors))


@lru_cache(maxsize=1)
def default_ruleset() -> RuleSet:
    """Catálogo por defecto (integradas + YAML + plugins), cargado una vez."""
    return build_ruleset()
