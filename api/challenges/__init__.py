"""Catálogo de retos de corrección: carpetas `data/<id>/` con `reto.yaml`, `vulnerable.py` y `solucion.py`.

La solución de referencia solo la usan las pruebas (garantiza que cada reto tiene arreglo); la API nunca la expone.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

DATA = Path(__file__).resolve().parent / "data"
LEVELS = ("básico", "intermedio", "avanzado")


@dataclass(frozen=True)
class Challenge:
    id: str
    order: int
    title: str
    level: str
    rules: tuple[str, ...]
    cwe: str
    filename: str
    keep: tuple[str, ...]
    summary: str
    statement: str
    hints: tuple[str, ...]
    starter: str
    solution: str


def _load(folder: Path) -> Challenge:
    meta = yaml.safe_load((folder / "reto.yaml").read_text(encoding="utf-8"))
    ch = Challenge(
        id=folder.name, order=int(meta["order"]), title=meta["title"], level=meta["level"],
        rules=tuple(meta["rules"]), cwe=meta["cwe"], filename=meta["filename"], keep=tuple(meta.get("keep") or ()),
        summary=meta["summary"], statement=meta["statement"], hints=tuple(meta.get("hints") or ()),
        starter=(folder / "vulnerable.py").read_text(encoding="utf-8"),
        solution=(folder / "solucion.py").read_text(encoding="utf-8"),
    )
    if ch.level not in LEVELS:
        raise ValueError(f"{folder.name}: nivel desconocido {ch.level!r}")
    if not ch.rules:
        raise ValueError(f"{folder.name}: el reto debe indicar al menos una regla")
    return ch


@lru_cache(maxsize=1)
def catalog() -> dict[str, Challenge]:
    items = [_load(d) for d in sorted(DATA.iterdir()) if (d / "reto.yaml").is_file()]
    return {c.id: c for c in sorted(items, key=lambda c: (c.order, c.id))}


def get(challenge_id: str) -> Challenge | None:
    return catalog().get(challenge_id)
