"""Reporte de la infraestructura: pruebas de Terraform superadas y costo mensual estimado.

Uso (en el workflow infra.yml):
    python scripts/reporte_terraform.py --junit infra/resultado-pruebas.xml \
        [--plan infra/plan.json] --salida reporte-infra.md

Costos: Infracost no cubre Render ni Neon, así que se usa la tabla PRECIOS de abajo
(precio de lista mensual en USD de cada plan). Si hay plan.json (terraform show -json)
se leen los planes reales; si no, los valores por defecto de infra/variables.tf.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]

# Precio de lista mensual (USD). Solo se ponen cifras comprobadas en la documentación de
# Render (render.com/pricing y sus artículos de precios, noviembre de 2026); el resto queda
# como None y el reporte dice "consultar". Los planes de pago de Neon cobran por uso.
PRECIOS = {
    "render_web_service": {"free": 0, "starter": 7, "standard": 25},
    "render_keyvalue": {"free": 0},
    "neon_project": {"free": 0},
}
NOMBRES = {"render_web_service": "Servicio web (Render)", "render_keyvalue": "Key Value (Render)",
           "neon_project": "PostgreSQL (Neon)"}


# --- Pruebas -----------------------------------------------------------------------------------

def pruebas(ruta: Path) -> list[str]:
    if not ruta.is_file():
        return ["No se encontró el resultado de `terraform test`.", ""]
    raiz = ET.parse(ruta).getroot()  # XML que genera nuestro propio `terraform test`, no datos externos
    casos = raiz.iter("testcase")
    filas, ok, total = [], 0, 0
    for c in casos:
        total += 1
        fallo = c.find("failure") is not None or c.find("error") is not None
        salto = c.find("skipped") is not None
        estado = "fallida" if fallo else ("omitida" if salto else "superada")
        ok += estado == "superada"
        filas.append(f"| `{c.get('name')}` | {estado} | {float(c.get('time') or 0):.2f} s |")
    return [f"**{ok} de {total} pruebas superadas.**", "", "| Prueba | Resultado | Tiempo |",
            "|---|---|---:|", *filas, ""]


# --- Costos ------------------------------------------------------------------------------------

def planes_por_defecto() -> dict[str, str]:
    texto = (RAIZ / "infra" / "variables.tf").read_text(encoding="utf-8")
    defaults = dict(re.findall(r'variable "(\w+)"\s*{[^}]*?default\s*=\s*"([^"]*)"', texto, re.S))
    return {"render_web_service": defaults.get("plan_web", "free"),
            "render_keyvalue": defaults.get("plan_keyvalue", "free"),
            "neon_project": "free"}


def planes_del_plan(ruta: Path) -> dict[str, str]:
    plan = json.loads(ruta.read_text(encoding="utf-8"))
    out = {}
    for r in plan.get("planned_values", {}).get("root_module", {}).get("resources", []):
        if r["type"] in PRECIOS:
            out[r["type"]] = r.get("values", {}).get("plan") or "free"
    return out


def costos(plan: Path | None) -> list[str]:
    fuente = "plan de Terraform" if plan and plan.is_file() else "valores por defecto de infra/variables.tf"
    planes = planes_del_plan(plan) if plan and plan.is_file() else planes_por_defecto()
    filas, total = [], 0.0
    for tipo, nombre in NOMBRES.items():
        if tipo not in planes and plan and plan.is_file():
            continue  # el recurso no está en el plan (p. ej. Key Value opcional)
        p = planes.get(tipo, "free")
        precio = PRECIOS[tipo].get(p)
        total += precio or 0
        texto = f"${precio:,.2f}" if precio is not None else "consultar"
        filas.append(f"| {nombre} | `{tipo}` | {p} | {texto} |")
    return [f"Fuente de los planes: {fuente}.", "", "| Recurso | Tipo | Plan | USD/mes |", "|---|---|---|---:|",
            *filas, f"| **Total** | | | **${total:,.2f}** |", "",
            "Notas: el plan gratis de Render se duerme tras 15 min sin uso y Neon free se suspende a los 5 min. "
            "El ancho de banda extra y el uso por encima del plan se cobran aparte.", ""]


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--junit", default="infra/resultado-pruebas.xml")
    p.add_argument("--plan")
    p.add_argument("--salida", default="reporte-infra.md")
    a = p.parse_args()
    md = ["# Reporte de infraestructura (Terraform)", "", "## Pruebas", "", *pruebas(Path(a.junit)),
          "## Costo mensual estimado", "", *costos(Path(a.plan) if a.plan else None)]
    texto = "\n".join(md)
    Path(a.salida).write_text(texto, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(texto)
    print(texto)


if __name__ == "__main__":
    main()
