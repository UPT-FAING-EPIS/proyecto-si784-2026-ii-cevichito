"""Arma un reporte en Markdown con los resultados de SonarCloud, Semgrep y Snyk.

Uso (en el workflow de análisis estático):
    python scripts/reporte_calidad.py --semgrep semgrep.json --snyk-dir snyk \
        --sonar-key CLAVE --base docs/calidad/linea-base --salida reporte-calidad.md

"Superado" quiere decir que el hallazgo estaba en la línea base (el proyecto antes de la
refactorización) y ya no aparece. En SonarCloud se usan sus propios estados: issues cerrados
como corregidos y hotspots revisados.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

SEVERIDADES = ["critical", "high", "medium", "low", "info"]
SONAR = "https://sonarcloud.io"


# --- Lectura de cada herramienta ------------------------------------------------------------------

def leer_json(ruta: Path):
    if not ruta.is_file():
        return None
    return json.loads(ruta.read_text(encoding="utf-8"))


def semgrep(ruta: Path) -> dict[str, str] | None:
    """{clave: severidad}. La clave no usa la línea para que mover código no cuente como nuevo."""
    datos = leer_json(ruta)
    if datos is None:
        return None
    sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    return {f"{r['check_id']}|{r['path']}": sev.get(r["extra"].get("severity", ""), "low")
            for r in datos.get("results", [])}


def snyk_deps(ruta: Path) -> dict[str, str] | None:
    datos = leer_json(ruta)
    if datos is None:
        return None
    proyectos = datos if isinstance(datos, list) else [datos]
    out = {}
    for p in proyectos:
        for v in p.get("vulnerabilities", []):
            out[f"{v['id']}|{v.get('packageName', '')}"] = v.get("severity", "low")
    return out


def snyk_code(ruta: Path) -> dict[str, str] | None:
    datos = leer_json(ruta)
    if datos is None:
        return None
    nivel = {"error": "high", "warning": "medium", "note": "low"}
    out = {}
    for run in datos.get("runs", []):
        for r in run.get("results", []):
            loc = r.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            out[f"{r.get('ruleId')}|{loc}"] = nivel.get(r.get("level", "note"), "low")
    return out


# --- SonarCloud ------------------------------------------------------------------------------------

def sonar_get(ruta: str, **params):
    token = os.environ.get("SONAR_TOKEN", "")
    req = urllib.request.Request(f"{SONAR}/api/{ruta}?{urllib.parse.urlencode(params)}")
    if token:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{token}:".encode()).decode())
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def sonar(clave: str) -> dict | None:
    if not clave:
        return None
    try:
        filas = []
        for tipo, nombre in (("BUG", "Bugs"), ("VULNERABILITY", "Vulnerabilities"), ("CODE_SMELL", "Code smells")):
            abiertos = sonar_get("issues/search", componentKeys=clave, types=tipo, resolved="false", ps=1)["total"]
            corregidos = sonar_get("issues/search", componentKeys=clave, types=tipo, resolved="true",
                                   resolutions="FIXED", ps=1)["total"]
            filas.append((nombre, abiertos, corregidos))
        por_revisar = sonar_get("hotspots/search", projectKey=clave, status="TO_REVIEW", ps=1)["paging"]["total"]
        revisados = sonar_get("hotspots/search", projectKey=clave, status="REVIEWED", ps=1)["paging"]["total"]
        filas.append(("Security Hotspots", por_revisar, revisados))
        gate = sonar_get("qualitygates/project_status", projectKey=clave)["projectStatus"]["status"]
        return {"filas": filas, "gate": gate, "url": f"{SONAR}/dashboard?id={clave}"}
    except Exception as exc:  # noqa: BLE001 - el reporte no debe romper el workflow
        return {"error": str(exc)}


# --- Markdown --------------------------------------------------------------------------------------

def tabla_severidad(actual: dict[str, str], base: dict[str, str] | None) -> list[str]:
    cuenta = Counter(actual.values())
    superados = Counter(s for k, s in (base or {}).items() if k not in actual)
    nuevos = Counter(s for k, s in actual.items() if base is not None and k not in base)
    lineas = ["| Severidad | Actuales | Superados | Nuevos |", "|---|---:|---:|---:|"]
    for s in SEVERIDADES:
        if cuenta[s] or superados[s] or nuevos[s]:
            lineas.append(f"| {s} | {cuenta[s]} | {superados[s] if base is not None else '—'} | "
                          f"{nuevos[s] if base is not None else '—'} |")
    total_sup = sum(superados.values()) if base is not None else "—"
    lineas.append(f"| **Total** | **{len(actual)}** | **{total_sup}** | "
                  f"**{sum(nuevos.values()) if base is not None else '—'}** |")
    return lineas


def seccion(titulo: str, actual, base) -> list[str]:
    if actual is None:
        return [f"### {titulo}", "", "No se ejecutó (falta el resultado o el token).", ""]
    return [f"### {titulo}", "", *tabla_severidad(actual, base), ""]


def armar(args) -> str:
    base = Path(args.base) if args.base else None
    snyk = Path(args.snyk_dir) if args.snyk_dir else None

    def b(fn, nombre):
        return fn(base / nombre) if base else None

    md = ["# Reporte de calidad y seguridad", "",
          "**Superados**: hallazgos de la línea base (el proyecto antes de la refactorización) que ya no "
          "aparecen. **Nuevos**: los que no estaban en la línea base.", ""]

    md += ["## SonarCloud", ""]
    s = sonar(args.sonar_key)
    if s is None:
        md += ["No se ejecutó (falta la clave del proyecto).", ""]
    elif "error" in s:
        md += [f"No se pudo leer la API de SonarCloud: `{s['error']}`", ""]
    else:
        md += [f"Quality Gate: **{s['gate']}** · [ver panel]({s['url']})", "",
               "| Tipo | Abiertos | Superados |", "|---|---:|---:|"]
        md += [f"| {n} | {a} | {c} |" for n, a, c in s["filas"]]
        md += ["", "En Security Hotspots, *superados* son los ya revisados.", ""]

    md += ["## Semgrep", ""]
    md += seccion("Reglas p/default", semgrep(Path(args.semgrep)) if args.semgrep else None, b(semgrep, "semgrep.json"))

    md += ["## Snyk", ""]
    if snyk is None:
        md += ["No se ejecutó.", ""]
    else:
        md += seccion("Dependencias de Python", snyk_deps(snyk / "snyk-python.json"), b(snyk_deps, "snyk-python.json"))
        md += seccion("Dependencias de la web", snyk_deps(snyk / "snyk-web.json"), b(snyk_deps, "snyk-web.json"))
        md += seccion("Código (Snyk Code)", snyk_code(snyk / "snyk-code.sarif"), b(snyk_code, "snyk-code.sarif"))
        md += seccion("Imagen Docker", snyk_deps(snyk / "snyk-container.json"), b(snyk_deps, "snyk-container.json"))
    return "\n".join(md) + "\n"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--semgrep")
    p.add_argument("--snyk-dir")
    p.add_argument("--sonar-key", default="")
    p.add_argument("--base", help="Carpeta con los resultados de la línea base")
    p.add_argument("--salida", default="reporte-calidad.md")
    args = p.parse_args()
    texto = armar(args)
    Path(args.salida).write_text(texto, encoding="utf-8")
    resumen = os.environ.get("GITHUB_STEP_SUMMARY")
    if resumen:
        with open(resumen, "a", encoding="utf-8") as f:
            f.write(texto)
    print(texto)


if __name__ == "__main__":
    main()
