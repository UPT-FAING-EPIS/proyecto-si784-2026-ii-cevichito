"""Genera la documentación del proyecto a partir del código y la escribe en el README.

Saca del código:
  - el diccionario de datos y el diagrama entidad-relación (modelos de SQLAlchemy),
  - el diagrama de clases (modelos y clases principales del motor),
  - el diagrama de componentes (rutas registradas en Flask y paquetes),
  - el diagrama de despliegue (docker-compose.yml y render.yaml).

Escribe cada parte en docs/arquitectura/ y un resumen con los diagramas en README.md, entre
las marcas <!-- DOCS:INICIO --> y <!-- DOCS:FIN -->. Si no cambió nada, no toca los archivos.

Uso:  python scripts/generar_docs.py            (escribe)
      python scripts/generar_docs.py --check    (falla si la documentación está desactualizada)
"""

from __future__ import annotations

import argparse
import dataclasses
import inspect
import os
import sys
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "solo-para-generar-docs-0123456789abcdef")
os.environ.setdefault("SESSION_HMAC_KEY", "solo-para-generar-docs-0123456789abcdef")
os.environ.setdefault("DATABASE_URL", "sqlite://")

INICIO, FIN = "<!-- DOCS:INICIO -->", "<!-- DOCS:FIN -->"
SALIDA = RAIZ / "docs" / "arquitectura"


# --- Base de datos ---------------------------------------------------------------------------------

def tablas():
    from api.extensions import db
    from api import models  # noqa: F401  (registra los modelos)

    return sorted(db.metadata.tables.values(), key=lambda t: t.name)


def tipo(col) -> str:
    try:
        return str(col.type.compile()).lower()
    except Exception:  # noqa: BLE001 - tipos propios sin dialecto
        return type(col.type).__name__.lower()


def descripcion_tabla(t) -> str:
    from api.models import entities

    for _, cls in inspect.getmembers(entities, inspect.isclass):
        if getattr(cls, "__tablename__", None) == t.name and cls.__doc__:
            return " ".join(cls.__doc__.split())
    return ""


def descripcion_columna(c) -> str:
    if c.comment or c.doc:
        return c.comment or c.doc
    if c.primary_key:
        return "Identificador de la fila."
    for fk in c.foreign_keys:
        return f"Referencia a `{fk.column.table.name}`."
    if c.name.endswith("_at"):
        return f"Fecha y hora (UTC): {c.name[:-3].replace('_', ' ')}."
    return ""


def diccionario() -> str:
    md = ["# Diccionario de datos", "", "Generado desde los modelos de SQLAlchemy (`api/models/entities.py`).", ""]
    for t in tablas():
        md += [f"## `{t.name}`", ""]
        texto = t.comment or descripcion_tabla(t)
        if texto:
            md += [texto, ""]
        md += ["| Columna | Tipo | Nulo | Clave | Por defecto | Descripción |", "|---|---|---|---|---|---|"]
        for c in t.columns:
            clave = []
            if c.primary_key:
                clave.append("PK")
            for fk in c.foreign_keys:
                clave.append(f"FK → `{fk.column.table.name}.{fk.column.name}`")
            if c.unique:
                clave.append("único")
            defecto = ""
            if c.default is not None and getattr(c.default, "is_scalar", False):
                defecto = f"`{c.default.arg}`"
            elif c.server_default is not None:
                defecto = f"`{getattr(c.server_default, 'arg', '')}`"
            md.append(f"| `{c.name}` | {tipo(c)} | {'sí' if c.nullable else 'no'} | {', '.join(clave)} | "
                      f"{defecto} | {descripcion_columna(c).replace('|', '/')} |")
        if t.indexes:
            md += ["", "Índices: " + ", ".join(f"`{i.name}`" for i in sorted(t.indexes, key=lambda i: i.name or ""))]
        md.append("")
    return "\n".join(md)


def diagrama_er() -> str:
    lineas = ["erDiagram"]
    relaciones = []
    for t in tablas():
        lineas.append(f"    {t.name} {{")
        for c in t.columns:
            marca = " PK" if c.primary_key else (" FK" if c.foreign_keys else "")
            lineas.append(f"        {tipo(c).split('(')[0].replace(' ', '_')} {c.name}{marca}")
        lineas.append("    }")
        for c in t.columns:
            for fk in c.foreign_keys:
                destino = fk.column.table.name
                card = "|o--o{" if c.nullable else "||--o{"
                relaciones.append(f"    {destino} {card} {t.name} : \"{c.name}\"")
    return "\n".join(lineas + sorted(set(relaciones)))


# --- Clases ------------------------------------------------------------------------------------------

def clases_principales():
    from api.models import entities
    from sast.engine import context, runner
    from sast.rules import api as reglas

    modelos = [c for _, c in inspect.getmembers(entities, inspect.isclass)
               if c.__module__ == entities.__name__ and hasattr(c, "__tablename__")]
    motor = [reglas.RuleMeta, reglas.Finding, reglas.TraceStep, reglas.RuleError, reglas.PythonRule,
             runner.Engine, runner.EngineConfig, runner.ScanReport, context.FileContext]
    return modelos, motor


def atributos(cls) -> list[str]:
    if hasattr(cls, "__table__"):
        return [f"{tipo(c).split('(')[0].replace(' ', '_')} {c.name}" for c in cls.__table__.columns]
    if dataclasses.is_dataclass(cls):
        return [f"{getattr(f.type, '__name__', str(f.type)).split('[')[0].split('|')[0].strip()} {f.name}"
                for f in dataclasses.fields(cls)]
    return []


def metodos(cls) -> list[str]:
    propios = []
    for nombre, obj in vars(cls).items():
        if nombre.startswith("_") or not callable(obj) and not isinstance(obj, property):
            continue
        if isinstance(obj, property):
            continue
        propios.append(f"{nombre}()")
    return sorted(propios)


def diagrama_clases() -> str:
    modelos, motor = clases_principales()
    lineas = ["classDiagram", "    direction LR"]
    for cls in modelos + motor:
        lineas.append(f"    class {cls.__name__} {{")
        lineas += [f"        +{a}" for a in atributos(cls)[:12]]
        lineas += [f"        +{m}" for m in metodos(cls)[:8]]
        lineas.append("    }")
    nombres = {c.__tablename__: c.__name__ for c in modelos}
    relaciones = []
    for cls in modelos:
        for c in cls.__table__.columns:
            for fk in c.foreign_keys:
                destino = nombres.get(fk.column.table.name)
                if destino:
                    relaciones.append(f"    {destino} \"1\" <-- \"*\" {cls.__name__}")
    lineas += list(dict.fromkeys(relaciones))
    lineas += ["    Engine ..> FileContext : analiza", "    Engine ..> ScanReport : produce",
               "    ScanReport o-- Finding", "    Finding o-- TraceStep", "    PythonRule ..> RuleMeta",
               "    Occurrence ..> Finding : se guarda como"]
    return "\n".join(lineas)


# --- Componentes y despliegue ----------------------------------------------------------------------

def blueprints() -> list[tuple[str, str]]:
    from api.factory import create_app

    app = create_app()
    out = {}
    for regla in app.url_map.iter_rules():
        bp = regla.endpoint.split(".")[0] if "." in regla.endpoint else None
        if bp and regla.rule.startswith("/api/v1/"):
            prefijo = "/".join(regla.rule.split("/")[:4])
            out.setdefault(bp, prefijo)
    return sorted(out.items())


def diagrama_componentes() -> str:
    lineas = ["flowchart LR",
              "    usuario([Navegador])",
              "    subgraph web[\"SPA (React + Vite) — web/\"]",
              "        paginas[Páginas] --> cliente[api/client.ts]",
              "    end",
              "    subgraph api[\"API Flask — api/\"]",
              "        seguridad[security: sesión, CSRF, cabeceras]"]
    for bp, prefijo in blueprints():
        lineas.append(f"        c_{bp}[\"{bp} · {prefijo}\"]")
    lineas += ["        servicios[services]", "        modelos[models: SQLAlchemy]", "    end ",  # espacio: no es duplicado
               "    worker[[Worker — api/worker]]",
               "    motor[[Motor SAST — sast/]]",
               "    db[(PostgreSQL)]", "    kv[(Valkey: límite de peticiones)]",
               "    google{{Google OIDC}}", "    github{{GitHub: descarga de repos}}",
               "    usuario --> paginas", "    cliente -->|\"/api/v1, cookie + X-CSRF-Token\"| seguridad"]
    for bp, _ in blueprints():
        lineas.append(f"    seguridad --> c_{bp} --> servicios")
    lineas += ["    servicios --> modelos --> db", "    servicios --> kv", "    servicios --> google",
               "    worker -->|\"cola: SELECT … SKIP LOCKED\"| db", "    worker --> motor", "    worker --> github"]
    return "\n".join(dict.fromkeys(lineas))


def diagrama_despliegue() -> str:
    compose = yaml.safe_load((RAIZ / "docker-compose.yml").read_text(encoding="utf-8"))
    render = yaml.safe_load((RAIZ / "render.yaml").read_text(encoding="utf-8"))
    lineas = ["flowchart TB", "    subgraph local[\"Local: docker compose\"]"]
    for nombre, svc in compose["services"].items():
        imagen = svc.get("image", "imagen del proyecto")
        puertos = ", ".join(svc.get("ports", []))
        extra = f" · {puertos}" if puertos else ""
        lineas.append(f"        l_{nombre}[\"{nombre}<br/>{imagen}{extra}\"]")
    lineas.append("    end")
    lineas.append("    subgraph nube[\"Producción: Render + Neon\"]")
    for svc in render["services"]:
        plan = svc.get("plan", "")
        lineas.append(f"        r_{svc['name'].replace('-', '_')}[\"{svc['name']}<br/>{svc['type']} · plan {plan}\"]")
    lineas += ["        neon[(Neon PostgreSQL · plan free)]", "    end",
               "    l_api --> l_db", "    l_worker --> l_db", "    l_api --> l_valkey", "    l_migrate --> l_db",
               "    r_sast_studio --> neon", "    r_sast_studio --> r_sast_ratelimit",
               "    gh[GitHub Actions] -->|release: imagen + deploy hook| r_sast_studio"]
    return "\n".join(lineas)


# --- Escritura -----------------------------------------------------------------------------------------

def mermaid(codigo: str) -> str:
    return f"```mermaid\n{codigo}\n```"


def pages() -> list[str]:
    """Enlace a GitHub Pages; solo se conoce dentro de GitHub Actions."""
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return []
    dueno, nombre = repo.split("/", 1)
    return [f"- [Documentación técnica (clases y métodos)](https://{dueno.lower()}.github.io/{nombre}/), "
            "publicada en GitHub Pages"]


def documentos() -> dict[str, str]:
    er, clases, comp, desp = diagrama_er(), diagrama_clases(), diagrama_componentes(), diagrama_despliegue()
    return {
        "diccionario-datos.md": diccionario(),
        "diagrama-er.md": "# Diagrama entidad-relación\n\n" + mermaid(er) + "\n",
        "diagrama-clases.md": "# Diagrama de clases\n\n" + mermaid(clases) + "\n",
        "diagrama-componentes.md": "# Diagrama de componentes\n\n" + mermaid(comp) + "\n",
        "diagrama-despliegue.md": "# Diagrama de despliegue\n\n" + mermaid(desp) + "\n",
        "_readme": "\n".join([
            INICIO,
            "## Documentación generada",
            "",
            "Esta sección la actualiza el workflow `documentacion.yml` a partir del código. No la edites a mano.",
            "",
            f"- [Diccionario de datos](docs/arquitectura/diccionario-datos.md) ({len(tablas())} tablas)",
            "- [Diagrama entidad-relación](docs/arquitectura/diagrama-er.md)",
            "- [Diagrama de clases](docs/arquitectura/diagrama-clases.md)",
            "- [Diagrama de componentes](docs/arquitectura/diagrama-componentes.md)",
            "- [Diagrama de despliegue](docs/arquitectura/diagrama-despliegue.md)",
            *pages(),
            "",
            "<details><summary>Diagrama entidad-relación</summary>\n\n" + mermaid(er) + "\n\n</details>",
            "",
            "<details><summary>Diagrama de clases</summary>\n\n" + mermaid(clases) + "\n\n</details>",
            "",
            "<details><summary>Diagrama de componentes</summary>\n\n" + mermaid(comp) + "\n\n</details>",
            "",
            "<details><summary>Diagrama de despliegue</summary>\n\n" + mermaid(desp) + "\n\n</details>",
            FIN,
        ]),
    }


def readme_con(bloque: str, actual: str) -> str:
    if INICIO in actual and FIN in actual:
        a, b = actual.index(INICIO), actual.index(FIN) + len(FIN)
        return actual[:a] + bloque + actual[b:]
    # Primera vez: antes de «## Licencia» o al final.
    marca = "\n## Licencia"
    if marca in actual:
        i = actual.index(marca) + 1
        return actual[:i] + bloque + "\n\n" + actual[i:]
    return actual.rstrip("\n") + "\n\n" + bloque + "\n"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    docs = documentos()
    cambios = []
    SALIDA.mkdir(parents=True, exist_ok=True)
    for nombre, texto in docs.items():
        if nombre == "_readme":
            continue
        ruta = SALIDA / nombre
        if not ruta.is_file() or ruta.read_text(encoding="utf-8") != texto:
            cambios.append(ruta)
            if not args.check:
                ruta.write_text(texto, encoding="utf-8", newline="\n")
    readme = RAIZ / "README.md"
    actual = readme.read_text(encoding="utf-8")
    nuevo = readme_con(docs["_readme"], actual)
    if nuevo != actual:
        cambios.append(readme)
        if not args.check:
            readme.write_text(nuevo, encoding="utf-8", newline="\n")
    for r in cambios:
        print(("desactualizado: " if args.check else "actualizado: ") + str(r.relative_to(RAIZ)))
    if args.check and cambios:
        sys.exit(1)


if __name__ == "__main__":
    main()
