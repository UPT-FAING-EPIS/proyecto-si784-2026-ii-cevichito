"""Pruebas golden: la salida del motor sobre `samples/` no cambia sin revisión.

Para regenerar tras un cambio justificado:  UPDATE_GOLDEN=1 pytest tests/golden
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .snapshot import snapshot

GOLDEN = Path(__file__).parent / "samples.json"


def test_samples_match_golden() -> None:
    current = snapshot()
    if os.environ.get("UPDATE_GOLDEN") == "1" or not GOLDEN.exists():
        GOLDEN.write_text(json.dumps(current, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert current == expected
