"""Pruebas de aceptación: escenarios en Gherkin (español) contra el servidor real.

Reutilizan el servidor de `tests/e2e`. Se ejecutan aparte:

    python -m pytest -m aceptacion tests/aceptacion
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.e2e.conftest import Cliente, nuevo_usuario, servidor  # noqa: F401 - fixtures compartidas

AQUI = Path(__file__).parent


def pytest_configure(config):
    # Las etiquetas @CUS-xx de los .feature se convierten en marcas: `-m CUS-27` filtra por caso de uso.
    for n in range(1, 29):
        config.addinivalue_line("markers", f"CUS-{n:02d}: escenarios del caso de uso CUS-{n:02d} (FD03)")


def pytest_collection_modifyitems(config, items):
    for item in items:
        if AQUI in Path(str(item.fspath)).parents:
            item.add_marker(pytest.mark.aceptacion)
