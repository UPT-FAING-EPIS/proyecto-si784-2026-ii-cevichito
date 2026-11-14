"""Descarga segura del zipball de un repositorio público de GitHub (RNF-01).

- Solo se acepta `owner/repo` (y `ref` opcional) validados con regex: nunca una
  URL arbitraria, así no hay SSRF.
- Streaming con tope de bytes y timeouts; solo se siguen redirecciones a los
  hosts de GitHub.
- Sin `GITHUB_TOKEN` se descarga por `github.com/<repo>/archive/<ref>.zip`, la misma
  descarga que el botón «Download ZIP», que no gasta la cuota de la API (60 peticiones por
  hora y por IP sin autenticar; en un PaaS esa IP se comparte con otros servicios y la cuota
  suele estar agotada). Con token se usa la API autenticada (5000 por hora).
- `GITHUB_TOKEN` (opcional) vive solo en el servidor.
"""

from __future__ import annotations

import re
import time
from typing import Callable
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

OWNER_REPO = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
REF = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
ALLOWED_HOSTS = {"github.com", "api.github.com", "codeload.github.com"}
API = "https://api.github.com/repos/{repo}/zipball{ref}"
ARCHIVE = "https://github.com/{repo}/archive/{ref}.zip"
CHUNK = 64 * 1024
DOWNLOAD_DEADLINE_S = 120      # tiempo total máximo de la descarga, no por trozo
TICK_EVERY_S = 2.0


class GitHubError(Exception):
    def __init__(self, code: str, message: str, status: int = 422) -> None:
        super().__init__(code)
        self.code, self.message, self.status = code, message, status


@dataclass(frozen=True)
class RepoRef:
    repo: str
    ref: str | None = None

    @property
    def display(self) -> str:
        return f"{self.repo}@{self.ref}" if self.ref else self.repo


def parse_repo(repo: str, ref: str | None = None) -> RepoRef:
    value = (repo or "").strip()
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if value.lower().startswith(prefix):
            value = value[len(prefix):]
    value = value.removesuffix(".git").strip("/")
    if not OWNER_REPO.match(value):
        raise GitHubError("invalid_repo", "El repositorio debe tener la forma 'propietario/nombre'.")
    ref = (ref or "").strip() or None
    if ref is not None and (not REF.match(ref) or ".." in ref):
        raise GitHubError("invalid_ref", "La rama o etiqueta no es válida.")
    return RepoRef(value, ref)


def download_zipball(target: RepoRef, *, max_bytes: int, token: str | None = None,
                     session: requests.Session | None = None, deadline_s: float = DOWNLOAD_DEADLINE_S,
                     on_tick: Callable[[int], None] | None = None) -> bytes:
    """Descarga el zipball con límite de tamaño y de tiempo TOTAL.

    `on_tick(bytes_recibidos)` se llama cada pocos segundos (el worker lo usa como latido
    para que el reaper no crea que está caído). Si lanza una excepción, la descarga se corta.
    """
    started = last_tick = time.monotonic()
    if token:
        url = API.format(repo=target.repo, ref=f"/{target.ref}" if target.ref else "")
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "sast-studio",
                   "X-GitHub-Api-Version": "2022-11-28", "Authorization": f"Bearer {token}"}
    else:
        url = ARCHIVE.format(repo=target.repo, ref=target.ref or "HEAD")
        headers = {"User-Agent": "sast-studio"}
    http = session or requests.Session()
    try:
        with http.get(url, headers=headers, stream=True, timeout=(5, 15), allow_redirects=True) as resp:
            for hop in [*resp.history, resp]:
                host = urlparse(hop.url).hostname or ""
                if host not in ALLOWED_HOSTS:
                    raise GitHubError("bad_redirect", "Redirección inesperada desde GitHub.", 502)
            if resp.status_code == 404:
                raise GitHubError("repo_not_found", "Repositorio o rama no encontrados (¿es público?).", 404)
            if resp.status_code in (403, 429):
                raise GitHubError("github_rate_limited", "GitHub limitó las descargas. Inténtalo más tarde.", 429)
            if resp.status_code != 200:
                raise GitHubError("github_error", f"GitHub respondió {resp.status_code}.", 502)
            declared = int(resp.headers.get("Content-Length") or 0)
            if declared > max_bytes:
                raise GitHubError("repo_too_large", "El repositorio supera el tamaño máximo permitido.", 413)
            buf = bytearray()
            for chunk in resp.iter_content(CHUNK):
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise GitHubError("repo_too_large", "El repositorio supera el tamaño máximo permitido.", 413)
                now = time.monotonic()
                if now - started > deadline_s:
                    raise GitHubError("github_timeout", "La descarga desde GitHub tardó demasiado. Inténtalo más tarde.", 504)
                if on_tick is not None and now - last_tick >= TICK_EVERY_S:
                    last_tick = now
                    on_tick(len(buf))
            return bytes(buf)
    except requests.RequestException:
        raise GitHubError("github_unreachable", "No se pudo contactar con GitHub.", 502) from None
