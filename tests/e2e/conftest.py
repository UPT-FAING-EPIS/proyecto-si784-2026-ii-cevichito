"""Servidor real para las pruebas de sistema y de interfaz.

Arranca SAST Studio completo (migraciones, worker y web) con una base SQLite temporal, una
sola vez por sesión de pytest. Estas pruebas se ejecutan aparte:

    python -m pytest -m sistema tests/e2e      # sistema (HTTP contra el servidor real)
    python -m pytest -m ui tests/e2e           # interfaz (navegador real; requiere web/dist)
"""

from __future__ import annotations

import socket
import sys
import time
import uuid
from pathlib import Path

import pytest
import requests

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import servidor_pruebas  # noqa: E402


def _puerto_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def servidor(tmp_path_factory) -> str:
    port = _puerto_libre()
    tmp = tmp_path_factory.mktemp("servidor")
    procs = servidor_pruebas.arrancar(port, tmp / "pruebas.db", log_dir=REPO / "reportes" / "logs")
    yield f"http://127.0.0.1:{port}"
    servidor_pruebas.parar(procs)


class Cliente:
    """Un usuario que habla con la API igual que la web: cookie de sesión y X-CSRF-Token."""

    def __init__(self, base: str, email: str) -> None:
        self.base = base
        self.s = requests.Session()
        self.s.headers["Origin"] = base
        r = self.s.post(f"{base}/api/v1/auth/dev-login", json={"email": email}, timeout=10)
        assert r.status_code == 200, r.text
        self.s.headers["X-CSRF-Token"] = r.json()["csrf_token"]

    def get(self, path: str, **kw):
        return self.s.get(self.base + path, timeout=15, **kw)

    def post(self, path: str, **kw):
        return self.s.post(self.base + path, timeout=15, **kw)

    def patch(self, path: str, **kw):
        return self.s.patch(self.base + path, timeout=15, **kw)

    def esperar_escaneo(self, scan_id: str, limite: float = 90) -> dict:
        fin = time.monotonic() + limite
        while time.monotonic() < fin:
            scan = self.get(f"/api/v1/scans/{scan_id}").json()
            if scan["status"] not in ("queued", "running"):
                return scan
            time.sleep(0.5)
        raise AssertionError(f"El escaneo {scan_id} no terminó en {limite} s")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """En las pruebas de interfaz, adjunta al reporte HTML una captura del estado final."""
    outcome = yield
    rep = outcome.get_result()
    page = item.funcargs.get("page") if hasattr(item, "funcargs") else None
    if rep.when != "call" or page is None:
        return
    try:
        import base64

        import pytest_html

        png = base64.b64encode(page.screenshot(full_page=True)).decode()
        rep.extras = [*getattr(rep, "extras", []), pytest_html.extras.png(png, "Pantalla al terminar")]
    except Exception:  # noqa: BLE001 - la captura nunca debe romper la prueba
        pass


@pytest.fixture
def nuevo_usuario(servidor):
    def crear(prefijo: str = "estudiante") -> Cliente:
        return Cliente(servidor, f"{prefijo}-{uuid.uuid4().hex[:8]}@pruebas.test")

    return crear
