"""Pasos de los escenarios de aceptación (`features/*.feature`).

Cada escenario describe, en lenguaje del usuario, un criterio de aceptación de los casos de uso
del FD03. Los pasos hablan con SAST Studio por HTTP, como lo haría la web.
"""

from __future__ import annotations

import time

import pytest

# pytest-bdd es una herramienta de requirements-pruebas.txt: sin ella, el módulo se omite.
pytest.importorskip("pytest_bdd")
from pytest_bdd import given, parsers, scenarios, then, when  # noqa: E402

from api import challenges  # noqa: E402

scenarios("features")

CODIGOS = {
    "vulnerable": (
        "import sqlite3\n"
        "from flask import request\n\n\n"
        "def buscar():\n"
        '    nombre = request.args["nombre"]\n'
        '    db = sqlite3.connect("app.db")\n'
        "    return db.execute(\"SELECT * FROM usuarios WHERE nombre = '%s'\" % nombre).fetchall()\n"
    ),
}
CODIGOS["corregido"] = CODIGOS["vulnerable"].replace(
    "\"SELECT * FROM usuarios WHERE nombre = '%s'\" % nombre",
    '"SELECT * FROM usuarios WHERE nombre = ?", (nombre,)',
)
# Mismo fallo, desplazado una línea: la huella estable debe reconocerlo como el mismo issue.
CODIGOS["vulnerable con una línea más"] = "# comentario nuevo\n" + CODIGOS["vulnerable"]


# --- Contexto ---------------------------------------------------------------------------------

@given("que soy un estudiante con sesión iniciada", target_fixture="ctx")
def estudiante(nuevo_usuario):
    return {"cli": nuevo_usuario("aceptacion"), "nuevo_usuario": nuevo_usuario}


@given(parsers.parse('tengo un proyecto llamado "{nombre}"'))
def proyecto(ctx, nombre):
    r = ctx["cli"].post("/api/v1/projects", json={"name": nombre})
    assert r.status_code == 201, r.text
    ctx["pid"] = r.json()["id"]


# --- Escaneo ----------------------------------------------------------------------------------

def _analizar(ctx, codigo):
    cli = ctx["cli"]
    r = cli.post(f"/api/v1/projects/{ctx['pid']}/scans",
                 json={"source": "snippet", "filename": "app.py", "code": CODIGOS[codigo]})
    assert r.status_code == 202, r.text
    ctx["escaneo"] = cli.esperar_escaneo(r.json()["id"])
    ctx["hallazgos"] = cli.get(f"/api/v1/scans/{ctx['escaneo']['id']}/findings").json()["items"]


@given(parsers.parse('que analicé el código "{codigo}"'))
def ya_analice(ctx, codigo):
    _analizar(ctx, codigo)


@when(parsers.parse('analizo el código "{codigo}"'))
def analizo(ctx, codigo):
    _analizar(ctx, codigo)


@then("el escaneo termina correctamente")
def escaneo_ok(ctx):
    assert ctx["escaneo"]["status"] == "done", ctx["escaneo"]


@then(parsers.parse('aparece un hallazgo de la regla "{regla}" con severidad "{severidad}"'))
def aparece(ctx, regla, severidad):
    encontrados = [h for h in ctx["hallazgos"] if h["rule_id"] == regla]
    assert encontrados, f"No apareció {regla}: {[h['rule_id'] for h in ctx['hallazgos']]}"
    assert encontrados[0]["severity"] == severidad
    ctx["hallazgo"] = encontrados[0]


@then(parsers.parse('el hallazgo trae su explicación, su corrección y el CWE "{cwe}"'))
def explicado(ctx, cwe):
    issue = ctx["cli"].get(f"/api/v1/issues/{ctx['hallazgo']['issue_id']}").json()
    regla = issue["rule"]
    assert regla["explanation_es"].strip() and regla["remediation_es"].strip()
    assert regla["example_bad"].strip() and regla["example_good"].strip()
    assert any(cwe == c or cwe.endswith(f"-{c}") for c in map(str, regla["cwe"])), regla["cwe"]


@then(parsers.parse('no aparece ningún hallazgo de la regla "{regla}"'))
def no_aparece(ctx, regla):
    assert regla not in {h["rule_id"] for h in ctx["hallazgos"]}


# --- Seguimiento ------------------------------------------------------------------------------

@then(parsers.parse('la comparación con el escaneo anterior muestra "{regla}" como corregido'))
def comparacion(ctx, regla):
    diff = ctx["cli"].get(f"/api/v1/scans/{ctx['escaneo']['id']}/diff").json()
    assert regla in {h["rule_id"] for h in diff["fixed"]}, diff


def _issue(ctx, regla):
    items = ctx["cli"].get(f"/api/v1/projects/{ctx['pid']}/issues", params={"rule_id": regla}).json()["items"]
    assert len(items) == 1, items
    return items[0]


@given(parsers.parse('marqué el hallazgo "{regla}" como "{triage}" con la justificación "{texto}"'))
def marcar(ctx, regla, triage, texto):
    issue = _issue(ctx, regla)
    r = ctx["cli"].patch(f"/api/v1/issues/{issue['id']}", json={"triage": triage, "justification": texto})
    assert r.status_code == 200, r.text
    ctx["issue_id"] = issue["id"]


@then(parsers.parse('el hallazgo "{regla}" sigue marcado como "{triage}"'))
def sigue_marcado(ctx, regla, triage):
    issue = _issue(ctx, regla)
    assert issue["id"] == ctx["issue_id"], "Debía reconocerse como el mismo problema"
    assert issue["triage"] == triage


# --- Retos ------------------------------------------------------------------------------------

def _enviar(ctx, reto_id, codigo):
    r = ctx["cli"].post(f"/api/v1/challenges/{reto_id}/submissions", json={"code": codigo})
    ctx["reto"], ctx["respuesta"] = reto_id, r


@when(parsers.parse('envío el código de partida del reto "{reto}"'))
def enviar_partida(ctx, reto):
    _enviar(ctx, reto, challenges.get(reto).starter)


@when(parsers.parse('envío la solución del reto "{reto}"'))
def enviar_solucion(ctx, reto):
    _enviar(ctx, reto, challenges.get(reto).solution)


@when(parsers.parse('envío el código de partida del reto "{reto}" silenciado con "{marca}"'))
def enviar_silenciado(ctx, reto, marca):
    ch = challenges.get(reto)
    # Añade la marca al final de cada línea con hallazgo del código de partida.
    from sast.engine.runner import Engine, EngineConfig

    lineas = {f.line for f in Engine(None, EngineConfig()).scan_source(ch.starter, ch.filename).findings
              if f.rule_id in ch.rules}
    codigo = "\n".join(f"{t}  {marca}" if i in lineas else t
                       for i, t in enumerate(ch.starter.splitlines(), start=1)) + "\n"
    _enviar(ctx, reto, codigo)


@when(parsers.parse('envío un código sin las funciones del reto "{reto}"'))
def enviar_vacio(ctx, reto):
    _enviar(ctx, reto, "print('hola')\n")


@when(parsers.parse('envío el código "{codigo}" al reto "{reto}"'))
def enviar_codigo(ctx, codigo, reto):
    _enviar(ctx, reto, codigo)


@then(parsers.parse('el veredicto es "{estado}"'))
def veredicto(ctx, estado):
    assert ctx["respuesta"].status_code == 202, ctx["respuesta"].text
    url = f"/api/v1/challenges/{ctx['reto']}/attempt"
    fin = time.monotonic() + 90
    while time.monotonic() < fin:
        intento = ctx["cli"].get(url).json()
        if intento["state"] != "analizando":
            break
        time.sleep(0.5)
    assert intento["state"] == estado, intento


@then(parsers.parse('el reto "{reto}" aparece como superado en la lista'))
def en_la_lista(ctx, reto):
    lista = {c["id"]: c for c in ctx["cli"].get("/api/v1/challenges").json()}
    assert lista[reto]["state"] == "superado"


@then(parsers.parse('el envío se rechaza con el error "{codigo}"'))
def rechazado(ctx, codigo):
    r = ctx["respuesta"]
    assert r.status_code == 422, r.text
    assert r.json()["error"]["code"] == codigo


# --- Privacidad -------------------------------------------------------------------------------

@when("otro estudiante intenta abrir mi proyecto")
def otro_abre(ctx):
    ctx["otro"] = ctx["nuevo_usuario"]("otro")
    ctx["respuesta"] = ctx["otro"].get(f"/api/v1/projects/{ctx['pid']}")


@then(parsers.parse('recibe la respuesta "{codigo:d}"'))
def respuesta(ctx, codigo):
    assert ctx["respuesta"].status_code == codigo, ctx["respuesta"].text


@then("mi proyecto no aparece en su lista")
def no_en_lista(ctx):
    ids = {p["id"] for p in ctx["otro"].get("/api/v1/projects").json()["items"]}
    assert ctx["pid"] not in ids


@when("un visitante sin sesión pide la lista de proyectos", target_fixture="ctx")
def visitante(servidor):
    import requests

    return {"respuesta": requests.get(f"{servidor}/api/v1/projects", timeout=10)}
