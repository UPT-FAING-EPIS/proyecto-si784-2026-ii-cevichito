"""Huella estable de hallazgos `sastfp/v1`.

No depende del número de línea ni de la columna, así un hallazgo conserva su
identidad aunque el código se desplace. Inspirado en el `primaryLocationLineHash`
de GitHub (ventana de código sin espacios) y en el emparejado de SonarQube
(regla + hash de línea).

    norm_path    = ruta relativa con "/" y sin prefijos temporales
    norm_code    = líneas [line..end_line] (máx. 3) + 1 de contexto si es corta,
                   sin ningún espacio en blanco; en reglas de secretos el
                   contenido de los literales se sustituye por "S"
    snippet_hash = sha256(norm_code)
    occurrence   = 1..n entre hallazgos con igual (regla, ruta, snippet_hash)
    fingerprint  = sha256("v1|sast-studio|regla|ruta|snippet_hash|occurrence")
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Iterable, Sequence

from ..rules.api import Finding

VERSION = 1
TOOL = "sast-studio"
SARIF_KEY = "sastStudio/v1"
_WS = re.compile(r"\s+")
_STRING = re.compile(r"""("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')""")
_SECRET_RULES = ("generic/hardcoded-secret",)
_ZIPBALL_PREFIX = re.compile(r"^[^/]+-[^/]+-[0-9a-f]{7,40}/")


def normalize_path(path: str) -> str:
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    return _ZIPBALL_PREFIX.sub("", p)


def normalize_code(lines: Sequence[str], line: int, end_line: int, rule_id: str) -> str:
    start = max(1, line)
    end = min(len(lines), max(start, min(end_line, start + 2)))
    chunk = [lines[i - 1] for i in range(start, end + 1)] if lines else []
    text = "".join(chunk)
    if len(_WS.sub("", text)) < 12 and end < len(lines):
        text += lines[end]
    if rule_id in _SECRET_RULES:
        text = _STRING.sub('"S"', text)
    return _WS.sub("", text)


def line_hash(lines: Sequence[str], line: int) -> str:
    text = lines[line - 1] if 1 <= line <= len(lines) else ""
    return hashlib.sha256(_WS.sub("", text).encode("utf-8")).hexdigest()


def snippet_hash(lines: Sequence[str], finding: Finding) -> str:
    return hashlib.sha256(normalize_code(lines, finding.line, finding.end_line, finding.rule_id).encode("utf-8")).hexdigest()


def assign_fingerprints(findings: Iterable[Finding], sources: dict[str, Sequence[str]]) -> list[Finding]:
    """Devuelve los hallazgos con `fingerprint` calculado (orden estable por línea)."""
    items = sorted(findings, key=lambda f: f.sort_key())
    counters: dict[tuple[str, str, str], int] = defaultdict(int)
    out: list[Finding] = []
    for f in items:
        lines = sources.get(f.path, ())
        path = normalize_path(f.path)
        s_hash = snippet_hash(lines, f)
        key = (f.rule_id, path, s_hash)
        counters[key] += 1
        raw = f"v{VERSION}|{TOOL}|{f.rule_id}|{path}|{s_hash}|{counters[key]}"
        out.append(f.with_(fingerprint=hashlib.sha256(raw.encode("utf-8")).hexdigest()))
    return out
