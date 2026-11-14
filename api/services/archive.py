"""Lectura segura de ZIP en memoria (RNF-01), sin extraer nunca a disco.

Defensas (OWASP File Upload Cheat Sheet):
- Se cuentan los bytes **realmente leídos** con `zf.open()` en bloques de
  64 KiB; los tamaños de las cabeceras del ZIP pueden estar falsificados.
- Límites: número de entradas, tamaño por archivo (los mayores se omiten),
  total descomprimido y razón de compresión por entrada.
- Se rechazan rutas absolutas, `..`, unidades de Windows y symlinks.
- Solo se aceptan extensiones de código (lista blanca).
"""

from __future__ import annotations

import io
import posixpath
import stat
import zipfile
from dataclasses import dataclass, field

from sast.engine.languages import detect_language
from sast.engine.runner import DEFAULT_EXCLUDED_DIRS, DEFAULT_EXCLUDED_FILES

CHUNK = 64 * 1024


class ArchiveError(Exception):
    """ZIP inválido o que viola los límites. `status` es el código HTTP sugerido."""

    def __init__(self, code: str, message: str, status: int = 422) -> None:
        super().__init__(code)
        self.code = code
        self.message = message
        self.status = status


@dataclass(frozen=True)
class Limits:
    max_entries: int = 10_000
    max_entry_bytes: int = 10 * 1024 * 1024
    max_total_bytes: int = 200 * 1024 * 1024
    max_ratio: int = 100

    @classmethod
    def from_settings(cls, s) -> "Limits":
        return cls(max_entries=s.max_zip_entries, max_entry_bytes=s.max_entry_mb * 1024 * 1024,
                   max_total_bytes=s.max_total_uncompressed_mb * 1024 * 1024, max_ratio=s.max_compression_ratio)


@dataclass
class ArchiveContents:
    files: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    root_prefix: str = ""


def _safe_name(name: str) -> str | None:
    n = name.replace("\\", "/")
    if n.startswith("/") or (len(n) > 1 and n[1] == ":"):
        return None
    norm = posixpath.normpath(n)
    if norm.startswith("../") or norm == ".." or "/../" in f"/{norm}/":
        return None
    return norm


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(info.external_attr >> 16)


def read_zip(data: bytes, limits: Limits = Limits(), strip_root: bool = False) -> ArchiveContents:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError):
        raise ArchiveError("invalid_zip", "El archivo no es un ZIP válido.", 422) from None

    with zf:
        infos = zf.infolist()
        if len(infos) > limits.max_entries:
            raise ArchiveError("too_many_entries", f"El ZIP tiene más de {limits.max_entries} entradas.", 413)
        out = ArchiveContents()
        total = 0
        names = [i.filename for i in infos]
        if strip_root and names:
            first = names[0].split("/", 1)[0] + "/"
            if all(n.startswith(first) for n in names):
                out.root_prefix = first
        for info in infos:
            if info.is_dir():
                continue
            name = _safe_name(info.filename)
            if name is None:
                raise ArchiveError("unsafe_path", "El ZIP contiene rutas absolutas o con '..'.", 422)
            if _is_symlink(info):
                raise ArchiveError("symlink", "El ZIP contiene enlaces simbólicos.", 422)
            if out.root_prefix and name.startswith(out.root_prefix):
                name = name[len(out.root_prefix):]
            parts = name.split("/")
            if any(p in DEFAULT_EXCLUDED_DIRS for p in parts[:-1]) or parts[-1] in DEFAULT_EXCLUDED_FILES:
                continue
            if not detect_language(name):
                continue
            buf = bytearray()
            too_big = False
            with zf.open(info) as fh:
                while True:
                    chunk = fh.read(CHUNK)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    total += len(chunk)
                    if total > limits.max_total_bytes:
                        raise ArchiveError("too_large", "El contenido descomprimido supera el límite total.", 413)
                    if info.compress_size and len(buf) / max(info.compress_size, 1) > limits.max_ratio and len(buf) > CHUNK:
                        raise ArchiveError("compression_ratio", "Razón de compresión sospechosa (posible bomba ZIP).", 413)
                    if len(buf) > limits.max_entry_bytes:
                        too_big = True
                        break
            if too_big:
                out.skipped.append({"path": name, "reason": "archivo demasiado grande"})
                continue
            out.files.append((name, bytes(buf).decode("utf-8", errors="replace")))
        return out
