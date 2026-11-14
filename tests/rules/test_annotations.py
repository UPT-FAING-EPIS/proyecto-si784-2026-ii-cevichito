"""Arnés de pruebas de reglas basado en anotaciones `# ruleid:` / `# ok:`.

Cada archivo de `tests/rules/cases/` es un caso. El test falla si una línea
`ruleid` no produce el hallazgo o si una línea `ok` lo produce. Las anotaciones
`todoruleid` / `todook` documentan defectos conocidos y solo se reportan.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from .annotations import case_files, parse_expectations
from .engine_adapter import findings_for


@pytest.mark.parametrize("case", case_files(), ids=lambda p: p.name)
def test_rule_case(case: Path) -> None:
    exp = parse_expectations(case)
    assert exp.must or exp.must_not, f"{case.name} no tiene anotaciones ruleid/ok"

    got = {(rid, line) for rid, line in findings_for(case) if rid in exp.rule_ids}

    missing = sorted(exp.must - got)
    unexpected = sorted(exp.must_not & got)
    assert not missing, f"{case.name}: faltan hallazgos {missing}"
    assert not unexpected, f"{case.name}: hallazgos no esperados {unexpected}"


def test_every_case_file_has_annotations() -> None:
    files = case_files()
    assert files, "no hay casos de reglas"
    for f in files:
        exp = parse_expectations(f)
        assert exp.rule_ids, f"{f.name} sin anotaciones"
