"""Convierte los resultados de mutmut en un reporte HTML y un resumen en Markdown.

Se ejecuta después de `mutmut run` (en Linux o en la CI):

    python scripts/reporte_mutacion.py --html reportes/mutacion.html --md reportes/mutacion.md

Puntuación de mutación = mutantes muertos / (mutantes probados). Un mutante «sobreviviente» es
un cambio en el código (p. ej. `<` por `<=`) que ninguna prueba detectó: señala una prueba que
falta o una aserción débil.
"""

from __future__ import annotations

import argparse
import html
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ESTADOS = {
    "killed": "Muerto",
    "survived": "Sobrevive",
    "timeout": "Tiempo agotado",
    "no tests": "Sin pruebas",
    "skipped": "Omitido",
    "suspicious": "Sospechoso",
    "segfault": "Fallo del proceso",
}
LINEA = re.compile(r"^\s*(?P<nombre>\S+): (?P<estado>.+?)\s*$")


def mutmut(*args: str) -> str:
    return subprocess.run([sys.executable, "-m", "mutmut", *args], capture_output=True, text=True, check=True).stdout


def modulo(nombre: str) -> str:
    # sast.engine.fingerprint.x_normalize_path__mutmut_3 -> sast/engine/fingerprint.py
    base = nombre.split("__mutmut_")[0]
    partes = base.split(".")
    while partes and (partes[-1].startswith(("x_", "xǁ")) or "ǁ" in partes[-1]):
        partes.pop()
    return "/".join(partes) + ".py"


def funcion(nombre: str) -> str:
    base = nombre.split("__mutmut_")[0].split(".")[-1]
    return base.removeprefix("x_").replace("xǁ", "").replace("ǁ", ".")


def puntuacion(c: Counter) -> float:
    probados = sum(c.values()) - c["skipped"] - c["no tests"]
    return 100.0 * (c["killed"] + c["timeout"]) / probados if probados else 0.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--html", type=Path, required=True)
    ap.add_argument("--md", type=Path, required=True)
    args = ap.parse_args()

    filas = [m.groupdict() for ln in mutmut("results", "--all", "true").splitlines() if (m := LINEA.match(ln))]
    if not filas:
        print("No hay resultados de mutmut: ejecuta `mutmut run` primero.", file=sys.stderr)
        return 1

    total: Counter = Counter(f["estado"] for f in filas)
    por_modulo: dict[str, Counter] = defaultdict(Counter)
    for f in filas:
        por_modulo[modulo(f["nombre"])][f["estado"]] += 1
    sobrevivientes = [f["nombre"] for f in filas if f["estado"] == "survived"]
    difs = {n: mutmut("show", n) for n in sobrevivientes}
    fecha = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    score = puntuacion(total)

    # --- Markdown (resumen para la CI y para docs/pruebas) ---
    md = [
        "## Pruebas de mutación (mutmut)",
        "",
        f"**Puntuación de mutación: {score:.1f} %** ({total['killed'] + total['timeout']} de "
        f"{sum(total.values()) - total['skipped'] - total['no tests']} mutantes detectados). Generado: {fecha}.",
        "",
        "| Módulo | Mutantes | Muertos | Sobreviven | Puntuación |",
        "|---|---:|---:|---:|---:|",
    ]
    for mod, c in sorted(por_modulo.items()):
        md.append(f"| `{mod}` | {sum(c.values())} | {c['killed'] + c['timeout']} | {c['survived']} | {puntuacion(c):.1f} % |")
    args.md.parent.mkdir(parents=True, exist_ok=True)
    args.md.write_text("\n".join(md) + "\n", encoding="utf-8")

    # --- HTML ---
    def tabla_modulos() -> str:
        filas_html = "".join(
            f"<tr><td><code>{html.escape(mod)}</code></td><td>{sum(c.values())}</td><td>{c['killed'] + c['timeout']}</td>"
            f"<td>{c['survived']}</td><td>{c['no tests']}</td><td><b>{puntuacion(c):.1f} %</b></td></tr>"
            for mod, c in sorted(por_modulo.items())
        )
        return ("<table><thead><tr><th>Módulo</th><th>Mutantes</th><th>Muertos</th><th>Sobreviven</th>"
                f"<th>Sin pruebas</th><th>Puntuación</th></tr></thead><tbody>{filas_html}</tbody></table>")

    def bloque_sobrevivientes() -> str:
        if not sobrevivientes:
            return "<p>Ningún mutante sobrevivió: todas las alteraciones fueron detectadas por alguna prueba.</p>"
        return "".join(
            f"<details><summary><code>{html.escape(modulo(n))}</code> · {html.escape(funcion(n))} "
            f"<span class='muted'>({html.escape(n)})</span></summary><pre>{html.escape(difs[n])}</pre></details>"
            for n in sobrevivientes
        )

    estados = "".join(f"<li>{ESTADOS.get(k, k)}: <b>{v}</b></li>" for k, v in total.most_common())
    pagina = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reporte de mutación · SAST Studio</title>
<style>
body{{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:960px;margin:2rem auto;padding:0 16px;color:#1f2937}}
h1{{color:#1f3a5f}} table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #d1d5db;padding:6px 10px;text-align:left}} th{{background:#1f3a5f;color:#fff}}
.score{{font-size:2.4rem;font-weight:700;color:#1f3a5f}} .muted{{color:#6b7280;font-size:.85em}}
pre{{background:#f3f4f6;padding:10px;overflow-x:auto}} details{{margin:.4rem 0}} code{{font-family:Consolas,monospace}}
</style></head><body>
<h1>Reporte de pruebas de mutación</h1>
<p class="muted">SAST Studio · mutmut · {fecha}</p>
<p>Una prueba de mutación altera el código a propósito (por ejemplo, cambia <code>&lt;</code> por <code>&lt;=</code>
o <code>True</code> por <code>False</code>) y vuelve a ejecutar las pruebas unitarias. Si alguna prueba falla, el
mutante «muere»: las pruebas detectan ese error. Si todas pasan, el mutante «sobrevive» y señala una prueba que falta.</p>
<p class="score">{score:.1f} %</p><p>Puntuación de mutación global.</p>
<ul>{estados}</ul>
<h2>Por módulo</h2>{tabla_modulos()}
<h2>Mutantes sobrevivientes ({len(sobrevivientes)})</h2>{bloque_sobrevivientes()}
</body></html>"""
    args.html.parent.mkdir(parents=True, exist_ok=True)
    args.html.write_text(pagina, encoding="utf-8")
    print(f"Puntuación de mutación: {score:.1f} % · {dict(total)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
