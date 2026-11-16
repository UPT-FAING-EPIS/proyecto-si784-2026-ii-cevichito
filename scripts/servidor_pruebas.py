"""Levanta SAST Studio completo para las pruebas de sistema y de interfaz.

Base de datos SQLite temporal, migraciones reales, el worker de escaneos y Flask sirviendo la
API y la web compilada (`web/dist`). Solo para pruebas: usa el login de desarrollo.

    python scripts/servidor_pruebas.py --port 8765 --db pruebas.db

Las pruebas lo usan como módulo (`arrancar` / `parar`) desde `tests/e2e/conftest.py`.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def entorno(port: int, db: Path) -> dict[str, str]:
    return {
        **os.environ,
        "ENVIRONMENT": "dev",
        # Claves solo para pruebas locales: no protegen nada real.
        "SECRET_KEY": "pruebas-locales-0123456789abcdefghijklmnopqrstuv",
        "SESSION_HMAC_KEY": "pruebas-locales-hmac-0123456789abcdefghijklmn",
        "DATABASE_URL": f"sqlite:///{db.resolve().as_posix()}",
        "DEV_LOGIN_ENABLED": "true",
        "PUBLIC_ORIGIN": f"http://127.0.0.1:{port}",
        "SPA_DIR": str(REPO / "web" / "dist"),
        "RATELIMIT_ENABLED": "false",
        "FLASK_APP": "api.wsgi:app",
        "PYTHONUTF8": "1",
    }


def arrancar(port: int, db: Path, log_dir: Path | None = None) -> list[subprocess.Popen]:
    """Migra, arranca worker y web, y espera a que /readyz responda."""
    env = entorno(port, db)
    py = sys.executable
    subprocess.run([py, "-m", "flask", "db", "upgrade"], env=env, cwd=REPO, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def salida(nombre: str):
        if log_dir is None:
            return subprocess.DEVNULL
        log_dir.mkdir(parents=True, exist_ok=True)
        return open(log_dir / f"{nombre}.log", "w", encoding="utf-8")  # noqa: SIM115

    procs = [
        subprocess.Popen([py, "-m", "api.worker"], env=env, cwd=REPO,
                         stdout=salida("worker"), stderr=subprocess.STDOUT),
        subprocess.Popen([py, "-m", "flask", "run", "--host", "127.0.0.1", "--port", str(port), "--no-reload"],
                         env=env, cwd=REPO, stdout=salida("web"), stderr=subprocess.STDOUT),
    ]
    url = f"http://127.0.0.1:{port}/readyz"
    for _ in range(120):
        try:
            with urllib.request.urlopen(url, timeout=2) as r:  # noqa: S310 - URL local fija
                if r.status == 200:
                    return procs
        except OSError:
            pass
        if any(p.poll() is not None for p in procs):
            break
        time.sleep(0.5)
    parar(procs)
    raise RuntimeError("El servidor de pruebas no respondió en /readyz")


def parar(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        if p.poll() is None:
            p.terminate()
    for p in procs:
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--db", type=Path, default=Path("pruebas.db"))
    args = ap.parse_args()
    procs = arrancar(args.port, args.db)
    print(f"SAST Studio de pruebas en http://127.0.0.1:{args.port} (Ctrl+C para parar)")
    try:
        procs[1].wait()
    except KeyboardInterrupt:
        pass
    finally:
        parar(procs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
