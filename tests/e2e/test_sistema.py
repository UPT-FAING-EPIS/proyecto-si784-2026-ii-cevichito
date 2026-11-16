"""Pruebas de sistema: el producto completo (web + worker + base de datos) por HTTP.

A diferencia de `tests/api` (integración con el cliente de pruebas de Flask y el worker
llamado en el mismo proceso), aquí todo corre como en producción: procesos separados, el
worker reclamando de la cola de verdad y peticiones HTTP reales.
"""

from __future__ import annotations

import json

import pytest

from api import challenges

pytestmark = pytest.mark.sistema

VULNERABLE = '''import sqlite3
from flask import request


def buscar():
    nombre = request.args["nombre"]
    db = sqlite3.connect("app.db")
    return db.execute("SELECT * FROM usuarios WHERE nombre = '%s'" % nombre).fetchall()
'''

CORREGIDO = VULNERABLE.replace(
    '''"SELECT * FROM usuarios WHERE nombre = '%s'" % nombre''',
    '''"SELECT * FROM usuarios WHERE nombre = ?", (nombre,)''',
)


def _proyecto(cli, nombre="sistema") -> str:
    r = cli.post("/api/v1/projects", json={"name": nombre})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _escanear(cli, pid, codigo) -> dict:
    r = cli.post(f"/api/v1/projects/{pid}/scans",
                 json={"source": "snippet", "filename": "app.py", "code": codigo})
    assert r.status_code == 202, r.text
    return cli.esperar_escaneo(r.json()["id"])


def _hallazgos(cli, scan_id) -> list[dict]:
    return cli.get(f"/api/v1/scans/{scan_id}/findings").json()["items"]


def test_el_servicio_esta_vivo_y_con_migraciones(servidor):
    import requests

    assert requests.get(f"{servidor}/healthz", timeout=5).status_code == 200
    r = requests.get(f"{servidor}/readyz", timeout=5)
    assert r.status_code == 200
    assert r.json()["migrations"] == "head"


def test_la_web_se_sirve_con_cabeceras_de_seguridad(servidor):
    import requests

    r = requests.get(f"{servidor}/", timeout=5)
    assert r.status_code == 200
    assert "text/html" in r.headers["Content-Type"]
    assert "Content-Security-Policy" in r.headers
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_sin_sesion_la_api_responde_401(servidor):
    import requests

    assert requests.get(f"{servidor}/api/v1/projects", timeout=5).status_code == 401


def test_flujo_completo_escanear_corregir_y_comparar(nuevo_usuario):
    cli = nuevo_usuario()
    pid = _proyecto(cli)

    primero = _escanear(cli, pid, VULNERABLE)
    assert primero["status"] == "done", primero
    reglas = {h["rule_id"] for h in _hallazgos(cli, primero["id"])}
    assert "py/sql-injection" in reglas

    segundo = _escanear(cli, pid, CORREGIDO)
    assert segundo["status"] == "done", segundo
    assert "py/sql-injection" not in {h["rule_id"] for h in _hallazgos(cli, segundo["id"])}

    diff = cli.get(f"/api/v1/scans/{segundo['id']}/diff").json()
    assert diff["base_scan_id"] == primero["id"]
    assert "py/sql-injection" in {h["rule_id"] for h in diff["fixed"]}


def test_informes_sarif_json_y_html(nuevo_usuario):
    cli = nuevo_usuario()
    scan = _escanear(cli, _proyecto(cli), VULNERABLE)

    sarif = cli.get(f"/api/v1/scans/{scan['id']}/report", params={"format": "sarif"})
    assert sarif.status_code == 200
    doc = json.loads(sarif.text)
    assert doc["version"] == "2.1.0"
    assert any(r["ruleId"] == "py/sql-injection" for r in doc["runs"][0]["results"])

    assert cli.get(f"/api/v1/scans/{scan['id']}/report", params={"format": "json"}).status_code == 200
    html = cli.get(f"/api/v1/scans/{scan['id']}/report", params={"format": "html"})
    assert html.status_code == 200 and "<html" in html.text.lower()


def test_un_usuario_no_ve_los_proyectos_de_otro(nuevo_usuario):
    ana, beto = nuevo_usuario("ana"), nuevo_usuario("beto")
    pid = _proyecto(ana, "privado")
    assert beto.get(f"/api/v1/projects/{pid}").status_code == 404
    assert pid not in {p["id"] for p in beto.get("/api/v1/projects").json()["items"]}


def test_reto_de_correccion_de_principio_a_fin(nuevo_usuario):
    cli = nuevo_usuario()
    reto = challenges.get("01-login-sql")
    url = f"/api/v1/challenges/{reto.id}"

    assert cli.post(f"{url}/submissions", json={"code": reto.starter}).status_code == 202
    estado = _esperar_veredicto(cli, url)
    assert estado["state"] == "sigue"

    assert cli.post(f"{url}/submissions", json={"code": reto.solution}).status_code == 202
    estado = _esperar_veredicto(cli, url)
    assert estado["state"] == "superado"

    lista = {c["id"]: c for c in cli.get("/api/v1/challenges").json()}
    assert lista[reto.id]["state"] == "superado"


def _esperar_veredicto(cli, url, limite=90) -> dict:
    import time

    fin = time.monotonic() + limite
    while time.monotonic() < fin:
        estado = cli.get(f"{url}/attempt").json()
        if estado["state"] != "analizando":
            return estado
        time.sleep(0.5)
    raise AssertionError("El reto no recibió veredicto")
