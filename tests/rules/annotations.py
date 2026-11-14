"""Ubicación de los casos de reglas; la lógica del arnés vive en `sast.testing`."""

from __future__ import annotations

from pathlib import Path

from sast.testing import Expectations, parse_expectations  # noqa: F401  (reexportado)
from sast.testing import case_files as _case_files

CASES_DIR = Path(__file__).parent / "cases"


def case_files() -> list[Path]:
    return _case_files(CASES_DIR)
