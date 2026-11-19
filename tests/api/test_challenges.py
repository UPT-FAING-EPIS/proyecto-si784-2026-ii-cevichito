"""Retos de corrección: catálogo, solución de referencia y veredicto de la API."""

from __future__ import annotations

import pytest

import ast

from api import challenges
from api.errors import ApiError
from api.services.challenge_service import check_submission
from sast.engine.runner import Engine, EngineConfig
from sast.rules.api import Severity
from sast.rules.registry import default_ruleset

from .conftest import login
from .test_contract import drain

CATALOG = list(challenges.catalog().values())
URL = "/api/v1/challenges"


def _findings(code: str, filename: str):
    return [f for f in Engine(None, EngineConfig()).scan_source(code, filename).findings if not f.suppressed]


# --- Contenido: cada reto es resoluble ---------------------------------------------------------

def test_catalog_has_the_initial_challenges():
    assert len(CATALOG) >= 8
    assert [c.order for c in CATALOG] == sorted(c.order for c in CATALOG)
    known = set(default_ruleset().ids)
    for ch in CATALOG:
        assert set(ch.rules) <= known, ch.id
        assert ch.hints and ch.statement and ch.keep, ch.id


@pytest.mark.parametrize("ch", CATALOG, ids=lambda c: c.id)
def test_starter_code_triggers_the_challenge_rule(ch):
    assert {f.rule_id for f in _findings(ch.starter, ch.filename)} & set(ch.rules)


@pytest.mark.parametrize("ch", CATALOG, ids=lambda c: c.id)
def test_reference_solution_fixes_it_without_new_serious_findings(ch):
    found = _findings(ch.solution, ch.filename)
    assert not {f.rule_id for f in found} & set(ch.rules)
    assert not [f for f in found if f.severity >= Severity.HIGH]


# --- Borrar no es corregir: comportamiento exigido ----------------------------------------------------

class _S:
    max_snippet_kb = 1024


def _gut(code: str, keep) -> str:
    """Deja las funciones del enunciado con el cuerpo vacío (`pass`)."""
    tree = ast.parse(code)
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name in keep:
            n.body = [ast.Pass()]
    return ast.unparse(tree)


@pytest.mark.parametrize("ch", CATALOG, ids=lambda c: c.id)
def test_every_challenge_declares_required_behavior(ch):
    assert {r.function for r in ch.requires} == set(ch.keep), ch.id


@pytest.mark.parametrize("ch", CATALOG, ids=lambda c: c.id)
def test_starter_and_solution_keep_the_behavior(ch):
    assert check_submission(ch, ch.starter, _S)  # los requisitos no son más estrictos que el enunciado
    assert check_submission(ch, ch.solution, _S)


def test_dropping_the_token_is_not_a_fix():
    pagos = challenges.get("06-token-en-codigo")
    code = pagos.starter.replace('headers=cabeceras, ', '')
    code = code.replace('    cabeceras = {"Authorization": "Bearer " + PAGOS_TOKEN}' + chr(10), '')
    with pytest.raises(ApiError) as e:
        check_submission(pagos, code, _S)
    assert e.value.code == "behavior_missing" and "Authorization" in e.value.message


def test_plaintext_passwords_are_not_a_fix():
    md5 = challenges.get("05-claves-md5")
    code = md5.starter.replace("hashlib.md5(clave.encode()).hexdigest()", "clave")
    with pytest.raises(ApiError) as e:
        check_submission(md5, code, _S)
    assert e.value.code == "behavior_missing"


@pytest.mark.parametrize("ch", CATALOG, ids=lambda c: c.id)
def test_emptied_functions_are_rejected(ch):
    with pytest.raises(ApiError) as e:
        check_submission(ch, _gut(ch.solution, ch.keep), _S)
    assert e.value.code == "behavior_missing"


PING = challenges.get("02-ping-comandos")


TRUNCATED_PING = '''import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.ge
'''

PING_WITH_HELPER = '''import subprocess
from flask import Flask, request
app = Flask(__name__)


def _hacer_ping(host):
    return subprocess.run(["ping", "-c", "1", host]).returncode


@app.route("/ping")
def ping():
    return {"ok": _hacer_ping(request.args.get("host", "")) == 0}
'''


def test_truncated_ping_is_rejected():
    """Caso real: el envío cortado es Python válido y no tiene la vulnerabilidad, pero tampoco hace ping."""
    with pytest.raises(ApiError) as e:
        check_submission(PING, TRUNCATED_PING, _S)
    assert e.value.code == "behavior_missing" and "subprocess.run" in e.value.message


def test_fix_moved_to_a_helper_is_accepted():
    assert check_submission(PING, PING_WITH_HELPER, _S)


# --- API ----------------------------------------------------------------------------------------

SQL = challenges.get("01-login-sql")


def submit(api, code, ch=SQL):
    return api.post(f"{URL}/{ch.id}/submissions", json={"code": code})


def verdict(api, ch=SQL):
    r = api.get(f"{URL}/{ch.id}/attempt")
    assert r.status_code == 200
    return r.get_json()


def test_list_and_detail_never_expose_the_solution(api):
    r = api.get(URL)
    assert r.status_code == 200
    items = r.get_json()
    assert [i["id"] for i in items] == [c.id for c in CATALOG]
    assert {i["state"] for i in items} == {"sin_empezar"}
    d = api.get(f"{URL}/{SQL.id}").get_json()
    assert d["starter"] == SQL.starter and d["attempt"]["state"] == "sin_empezar"
    assert d["rule_details"][0]["id"] == "py/sql-injection"
    assert "solution" not in d and SQL.solution not in str(d)
    assert api.get(f"{URL}/no-existe").status_code == 404


def test_requires_session(client):
    assert client.get(URL).status_code == 401


def test_unchanged_code_still_fails_then_solution_passes(api):
    assert submit(api, SQL.starter).status_code == 202
    assert verdict(api)["state"] == "analizando"
    drain()
    v = verdict(api)
    assert v["state"] == "sigue" and v["submissions"] == 1
    assert v["remaining"][0]["rule_id"] == "py/sql-injection"

    assert submit(api, SQL.solution).status_code == 202
    drain()
    v = verdict(api)
    assert v["state"] == "superado" and v["solved_at"] and v["submissions"] == 2
    assert {i["id"]: i["state"] for i in api.get(URL).get_json()}[SQL.id] == "superado"
    # El intento es un proyecto oculto: no aparece en el panel de proyectos.
    assert api.get("/api/v1/projects").get_json()["items"] == []


def test_silencing_the_finding_does_not_count(api):
    code = SQL.starter.replace("fila = db.execute(consulta).fetchone()",
                               "fila = db.execute(consulta).fetchone()  # nosec")
    submit(api, code)
    drain()
    v = verdict(api)
    assert v["state"] == "silenciado" and v["silenced"]


def test_fixing_one_flaw_but_adding_another_is_reported(api):
    code = SQL.solution + "\n\n@app.route(\"/debug\")\ndef debug():\n    return str(eval(request.args.get(\"x\")))\n"
    submit(api, code)
    drain()
    v = verdict(api)
    assert v["state"] == "nuevo_fallo"
    assert v["new"][0]["rule_id"] == "py/dangerous-function"


@pytest.mark.parametrize("code, error", [
    ("", "empty_code"),
    ("def login(:\n", "syntax_error"),
    ("print('borré todo')\n", "missing_functions"),
])
def test_invalid_submissions_are_rejected_before_scanning(api, code, error):
    r = submit(api, code)
    assert r.status_code == 422 and r.get_json()["error"]["code"] == error
    assert verdict(api)["state"] == "sin_empezar"


def test_attempts_are_private(app, api):
    submit(api, SQL.solution)
    drain()
    other = login(app.test_client(), email="otro@example.com")
    assert verdict(other)["state"] == "sin_empezar"
    assert {i["state"] for i in other.get(URL).get_json()} == {"sin_empezar"}
