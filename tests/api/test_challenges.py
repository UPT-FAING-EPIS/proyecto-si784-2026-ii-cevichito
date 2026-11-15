"""Retos de corrección: catálogo, solución de referencia y veredicto de la API."""

from __future__ import annotations

import pytest

from api import challenges
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
