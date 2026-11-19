"""Pruebas de los scripts que generan la documentación y el reporte de calidad."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

RAIZ = Path(__file__).resolve().parents[1]


def cargar(nombre: str):
    spec = importlib.util.spec_from_file_location(nombre, RAIZ / "scripts" / f"{nombre}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_documentos_tienen_todas_las_tablas_y_diagramas():
    docs = cargar("generar_docs").documentos()
    for tabla in ("users", "projects", "scans", "issues", "occurrences"):
        assert f"## `{tabla}`" in docs["diccionario-datos.md"]
    assert "erDiagram" in docs["diagrama-er.md"]
    assert docs["diagrama-clases.md"].count("class ") >= 15
    assert "subgraph" in docs["diagrama-componentes.md"]
    assert "Render" in docs["diagrama-despliegue.md"]
    assert docs["_readme"].startswith("<!-- DOCS:INICIO -->")


def test_readme_reemplaza_solo_el_bloque():
    gen = cargar("generar_docs")
    antes = "# T\n\nintro\n\n<!-- DOCS:INICIO -->\nviejo\n<!-- DOCS:FIN -->\n\n## Licencia\nMIT\n"
    despues = gen.readme_con("<!-- DOCS:INICIO -->\nnuevo\n<!-- DOCS:FIN -->", antes)
    assert "nuevo" in despues and "viejo" not in despues and despues.endswith("## Licencia\nMIT\n")


def test_reporte_cuenta_superados_y_nuevos(tmp_path):
    rep = cargar("reporte_calidad")

    def semgrep(*reglas):
        return {"results": [{"check_id": r, "path": "app.py", "extra": {"severity": "ERROR"}} for r in reglas]}

    base, actual = tmp_path / "base", tmp_path / "actual"
    base.mkdir()
    actual.mkdir()
    (base / "semgrep.json").write_text(json.dumps(semgrep("a", "b", "c")))
    (actual / "semgrep.json").write_text(json.dumps(semgrep("c", "d")))
    texto = rep.armar(SimpleNamespace(base=str(base), snyk_dir=None, sonar_key="",
                                      semgrep=str(actual / "semgrep.json")))
    assert "| high | 2 | 2 | 1 |" in texto  # actuales c,d · superados a,b · nuevo d
