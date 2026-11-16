"""Reúne los reportes de pruebas en una página índice (HTML) y un resumen (Markdown).

Lee los resultados JUnit (`*.xml`) de cada carpeta de `reportes/` y enlaza los reportes HTML:

    python scripts/indice_reportes.py reportes

Deja `reportes/index.html` y `reportes/resumen.md` (que la CI muestra en el resumen del run).
"""

from __future__ import annotations

import html
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

SECCIONES = [
    ("1-unitarias", "1. Pruebas unitarias y de mutación",
     "Motor de análisis, reglas, huellas, informes y CLI, más cobertura y mutación (mutmut)."),
    ("2-integracion-sistema", "2. Pruebas de integración y de sistema",
     "API con la base de datos real (PostgreSQL 16) y el producto completo por HTTP (web + worker + BD)."),
    ("3-interfaz", "3. Pruebas de interfaz de usuario",
     "Recorridos de usuario en un navegador real (Chromium con Playwright), con capturas."),
    ("4-aceptacion", "4. Pruebas de aceptación",
     "Escenarios Gherkin en español (pytest-bdd) derivados de los casos de uso del FD03."),
]


def contar(xml: Path) -> dict[str, float]:
    raiz = ET.parse(xml).getroot()
    suites = [raiz] if raiz.tag == "testsuite" else list(raiz.iter("testsuite"))
    c = {"pruebas": 0, "fallos": 0, "errores": 0, "omitidas": 0, "tiempo": 0.0}
    for s in suites:
        c["pruebas"] += int(s.get("tests", 0))
        c["fallos"] += int(s.get("failures", 0))
        c["errores"] += int(s.get("errors", 0))
        c["omitidas"] += int(s.get("skipped", 0))
        c["tiempo"] += float(s.get("time", 0))
    return c


def main() -> int:
    raiz = Path(sys.argv[1] if len(sys.argv) > 1 else "reportes")
    fecha = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    filas_md = ["| Tipo | Reporte | Pruebas | Pasan | Fallan | Omitidas | Tiempo |", "|---|---|---:|---:|---:|---:|---:|"]
    bloques = []
    for carpeta, titulo, desc in SECCIONES:
        d = raiz / carpeta
        if not d.exists():
            bloques.append(f"<section><h2>{titulo}</h2><p class='muted'>Sin resultados en este run.</p></section>")
            continue
        filas = []
        for xml in sorted(d.glob("*.xml")):
            c = contar(xml)
            pasan = c["pruebas"] - c["fallos"] - c["errores"] - c["omitidas"]
            mal = c["fallos"] + c["errores"]
            nombre = xml.stem
            enlace = f"{carpeta}/{nombre}.html"
            estado = "ok" if mal == 0 else "mal"
            filas.append(
                f"<tr class='{estado}'><td><a href='{html.escape(enlace)}'>{html.escape(nombre)}</a></td>"
                f"<td>{c['pruebas']}</td><td>{pasan}</td><td>{mal}</td><td>{c['omitidas']}</td><td>{c['tiempo']:.1f} s</td></tr>"
            )
            filas_md.append(f"| {titulo} | {nombre} | {c['pruebas']} | {pasan} | {mal} | {c['omitidas']} | {c['tiempo']:.1f} s |")
        extras = []
        if (d / "cobertura" / "index.html").exists():
            extras.append(f"<a href='{carpeta}/cobertura/index.html'>Cobertura de código</a>")
        if (d / "mutacion.html").exists():
            extras.append(f"<a href='{carpeta}/mutacion.html'>Reporte de mutación</a>")
        bloques.append(
            f"<section><h2>{titulo}</h2><p>{desc}</p><table><thead><tr><th>Reporte</th><th>Pruebas</th>"
            f"<th>Pasan</th><th>Fallan</th><th>Omitidas</th><th>Tiempo</th></tr></thead><tbody>{''.join(filas)}</tbody>"
            f"</table>{'<p>' + ' · '.join(extras) + '</p>' if extras else ''}</section>"
        )
    resumen = ["## Reportes de pruebas de SAST Studio", "", f"Generado: {fecha}", "", *filas_md]
    mutacion = raiz / "1-unitarias" / "mutacion.md"
    if mutacion.exists():
        resumen += ["", mutacion.read_text(encoding="utf-8")]
    (raiz / "resumen.md").write_text("\n".join(resumen) + "\n", encoding="utf-8")
    (raiz / "index.html").write_text(f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reportes de pruebas · SAST Studio</title>
<style>
body{{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:960px;margin:2rem auto;padding:0 16px;color:#1f2937}}
h1,h2{{color:#1f3a5f}} table{{border-collapse:collapse;width:100%;margin:.5rem 0}}
th,td{{border:1px solid #d1d5db;padding:6px 10px;text-align:left}} th{{background:#1f3a5f;color:#fff}}
tr.mal td{{background:#fee2e2}} .muted{{color:#6b7280}} a{{color:#1d4ed8}}
</style></head><body>
<h1>Reportes de pruebas · SAST Studio</h1>
<p class="muted">Generado automáticamente por GitHub Actions · {fecha}</p>
{''.join(bloques)}
</body></html>""", encoding="utf-8")
    print("\n".join(resumen))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
