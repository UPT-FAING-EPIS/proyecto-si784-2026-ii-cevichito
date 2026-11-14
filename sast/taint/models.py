"""Carga y consulta de los modelos de taint (`models.yaml`)."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

DEFAULT_MODELS = Path(__file__).with_name("models.yaml")


@dataclass(frozen=True)
class SinkModel:
    kind: str
    call: str
    arg: int
    when_kwarg: tuple[tuple[str, Any], ...] = ()


@dataclass(frozen=True)
class TaintModels:
    source_calls: dict[str, str] = field(default_factory=dict)      # patrón -> descripción
    source_attrs: dict[str, str] = field(default_factory=dict)
    sinks: tuple[SinkModel, ...] = ()
    sink_descriptions: dict[str, str] = field(default_factory=dict)
    sanitizers: dict[str, frozenset[str]] = field(default_factory=dict)  # patrón -> tipos ("*" = todos)

    # -- consultas (con caché por nombre calificado) -------------------------------
    def _cached(self, table: str, qualname: str, compute):
        caches = self.__dict__.setdefault("_caches", {})
        cache = caches.setdefault(table, {})
        if qualname not in cache:
            cache[qualname] = compute()
        return cache[qualname]

    def match_source_call(self, qualname: str) -> str | None:
        return self._cached("sc", qualname, lambda: _first_match(qualname, self.source_calls))

    def match_source_attr(self, qualname: str) -> str | None:
        return self._cached("sa", qualname, lambda: _first_match(qualname, self.source_attrs))

    def match_sanitizer(self, qualname: str) -> frozenset[str] | None:
        def compute():
            for pattern, kinds in self.sanitizers.items():
                if _matches(qualname, pattern):
                    return kinds
            return None
        return self._cached("san", qualname, compute)

    def match_sinks(self, qualname: str) -> list[SinkModel]:
        return self._cached("sink", qualname, lambda: [s for s in self.sinks if _matches(qualname, s.call)])


def _matches(qualname: str, pattern: str) -> bool:
    return qualname == pattern or ("*" in pattern and fnmatchcase(qualname, pattern))


def _first_match(qualname: str, table: dict[str, str]) -> str | None:
    for pattern, desc in table.items():
        if _matches(qualname, pattern):
            return desc
    return None


def parse_models(data: dict[str, Any]) -> TaintModels:
    source_calls: dict[str, str] = {}
    source_attrs: dict[str, str] = {}
    for spec in (data.get("sources") or {}).values():
        desc = spec.get("description", "fuente")
        for c in spec.get("calls", []) or []:
            source_calls[c] = desc
        for a in spec.get("attributes", []) or []:
            source_attrs[a] = desc
    sinks: list[SinkModel] = []
    sink_desc: dict[str, str] = {}
    for kind, spec in (data.get("sinks") or {}).items():
        sink_desc[kind] = spec.get("description", kind)
        for entry in spec.get("calls", []) or []:
            when = tuple(sorted((entry.get("when_kwarg") or {}).items()))
            sinks.append(SinkModel(kind=kind, call=entry["call"], arg=int(entry.get("arg", 0)), when_kwarg=when))
    sanitizers: dict[str, frozenset[str]] = {}
    for kind, names in (data.get("sanitizers") or {}).items():
        for name in names or []:
            sanitizers[name] = sanitizers.get(name, frozenset()) | {kind}
    return TaintModels(source_calls, source_attrs, tuple(sinks), sink_desc, sanitizers)


@lru_cache(maxsize=8)
def load_models(path: str | None = None) -> TaintModels:
    p = Path(path) if path else DEFAULT_MODELS
    return parse_models(yaml.safe_load(p.read_text(encoding="utf-8")) or {})
