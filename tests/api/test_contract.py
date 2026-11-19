"""F6: pruebas de contrato de la API v1 (una por fila de la tabla 4.1) y BOLA.

Las pruebas actúan como la SPA: mismo origen, cookie de sesión y X-CSRF-Token.
El worker se ejecuta de forma síncrona (`drain`) para no depender de procesos externos.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from api.extensions import db
from api.worker import queue
from api.worker.runner import process

from .conftest import ORIGIN, login, make_settings

VULN = '''import hashlib
import pickle
from flask import request
import os

def firma(data):
    return hashlib.md5(data).hexdigest()

def cargar(blob):
    return pickle.loads(blob)

def ping():
    os.system("ping " + request.args.get("h"))
'''
SETTINGS = make_settings()


def drain():
    while (sid := queue.claim("test-worker")) is not None:
        process(sid, SETTINGS)


def new_project(api, name="demo") -> str:
    r = api.post("/api/v1/projects", json={"name": name})
    assert r.status_code == 201, r.get_json()
    return r.get_json()["id"]


def scan_snippet(api, pid, code=VULN, filename="app.py", **extra) -> str:
    r = api.post(f"/api/v1/projects/{pid}/scans", json={"source": "snippet", "filename": filename, "code": code, **extra})
    assert r.status_code == 202, r.get_json()
    assert r.headers["Location"] == f"/api/v1/scans/{r.get_json()['id']}"
    assert r.get_json()["status"] == "queued"
    return r.get_json()["id"]


@pytest.fixture
def ready(api):
    """Proyecto con un escaneo terminado."""
    pid = new_project(api)
    sid = scan_snippet(api, pid)
    drain()
    return api, pid, sid


# --- Salud y auth (tabla 4.1) ---------------------------------------------------------------

def test_health_endpoints(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code in (200, 503)


def test_me_returns_whitelisted_fields(api):
    assert set(api.get("/api/v1/auth/me").get_json()) == {"id", "email", "name", "csrf_token", "is_admin"}


# --- Reglas ------------------------------------------------------------------------------------

def test_rules_catalog(api):
    rules = api.get("/api/v1/rules").get_json()
    assert len(rules) >= 12
    expected = {"id", "name", "severity", "confidence", "cwe", "owasp", "kind", "languages", "engine",
                "explanation_es", "example_bad", "example_good", "references"}
    assert expected <= set(rules[0])
    py = api.get("/api/v1/rules?language=python&severity=critical").get_json()
    assert py and all(r["severity"] == "critical" and "python" in r["languages"] for r in py)
    one = api.get("/api/v1/rules/py/weak-hash")
    assert one.status_code == 200 and one.get_json()["id"] == "py/weak-hash"
    assert api.get("/api/v1/rules/py/no-existe").status_code == 404


def test_rules_require_session(client):
    assert client.get("/api/v1/rules", base_url=ORIGIN).status_code == 401


# --- Proyectos -------------------------------------------------------------------------------------

def test_project_crud(api):
    pid = new_project(api, "uno")
    assert api.post("/api/v1/projects", json={"name": "uno"}).status_code == 409
    assert api.post("/api/v1/projects", json={"name": ""}).status_code == 400
    assert api.post("/api/v1/projects", json={"name": "x" * 121}).status_code == 400
    assert api.post("/api/v1/projects", data="no-json", headers={"Content-Type": "text/plain"}).status_code == 415
    listing = api.get("/api/v1/projects").get_json()
    assert listing["items"][0]["id"] == pid and listing["next_cursor"] is None
    detail = api.get(f"/api/v1/projects/{pid}").get_json()
    assert set(detail["open_by_severity"]) == {"critical", "high", "medium", "low", "info"}
    r = api.patch(f"/api/v1/projects/{pid}", json={"name": "renombrado"})
    assert r.status_code == 200 and r.get_json()["name"] == "renombrado"
    assert api.delete(f"/api/v1/projects/{pid}").status_code == 204
    assert api.get(f"/api/v1/projects/{pid}").status_code == 404


def test_project_pagination(api):
    for i in range(3):
        new_project(api, f"p{i}")
    first = api.get("/api/v1/projects?limit=2").get_json()
    assert len(first["items"]) == 2 and first["next_cursor"]
    second = api.get(f"/api/v1/projects?limit=2&cursor={first['next_cursor']}").get_json()
    assert len(second["items"]) == 1 and second["next_cursor"] is None
    assert api.get("/api/v1/projects?cursor=@@@").status_code == 400


# --- Escaneos ---------------------------------------------------------------------------------------

def test_scan_lifecycle_and_findings(ready):
    api, pid, sid = ready
    scan = api.get(f"/api/v1/scans/{sid}").get_json()
    assert scan["status"] == "done" and scan["progress"] == {"files_done": 1, "files_total": 1}
    assert scan["summary"]["by_severity"]["critical"] >= 2 and scan["summary"]["new"] == scan["summary"]["total"] + scan["summary"]["suppressed"]
    findings = api.get(f"/api/v1/scans/{sid}/findings").get_json()["items"]
    rule_ids = {f["rule_id"] for f in findings}
    assert {"py/weak-hash", "py/insecure-deserialization", "py/command-injection"} <= rule_ids
    inj = next(f for f in findings if f["rule_id"] == "py/command-injection")
    assert inj["trace"] and inj["change"] == "new" and inj["triage"] == "untriaged"
    keys = {"occurrence_id", "issue_id", "rule_id", "severity", "confidence", "path", "start_line", "end_line",
            "message", "snippet", "trace", "change", "triage", "suppressed"}
    assert keys <= set(inj)
    crit = api.get(f"/api/v1/scans/{sid}/findings?severity=critical").get_json()["items"]
    assert crit and all(f["severity"] == "critical" for f in crit)
    assert api.get(f"/api/v1/scans/{sid}/findings?change=bogus").status_code == 400
    listing = api.get(f"/api/v1/projects/{pid}/scans").get_json()
    assert listing["items"][0]["id"] == sid


def test_zip_upload_scan(api):
    pid = new_project(api)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/app.py", VULN)
    r = api.post(f"/api/v1/projects/{pid}/scans", data={"file": (io.BytesIO(buf.getvalue()), "p.zip")},
                 content_type="multipart/form-data")
    assert r.status_code == 202, r.get_json()
    drain()
    scan = api.get(f"/api/v1/scans/{r.get_json()['id']}").get_json()
    assert scan["status"] == "done" and scan["source"] == "zip" and scan["files_scanned"] == 1


@pytest.mark.parametrize("payload, status", [
    ({"source": "snippet", "filename": "a.py", "code": ""}, 422),
    ({"source": "snippet", "filename": "a.exe", "code": "x"}, 422),
    ({"source": "github", "repo": "http://169.254.169.254/"}, 422),
    ({"source": "ftp"}, 422),
    ({"source": "snippet", "filename": "a.py", "code": "x=1", "rules": ["no/existe"]}, 422),
])
def test_scan_creation_validation(api, payload, status):
    pid = new_project(api)
    assert api.post(f"/api/v1/projects/{pid}/scans", json=payload).status_code == status


def test_upload_too_large_is_413(app):
    app.config["MAX_CONTENT_LENGTH"] = 1024
    api = login(app.test_client())
    pid = new_project(api)
    r = api.post(f"/api/v1/projects/{pid}/scans", data={"file": (io.BytesIO(b"x" * 5000), "big.zip")},
                 content_type="multipart/form-data")
    assert r.status_code == 413 and r.get_json()["error"]["code"] == "payload_too_large"


def test_cancel_scan(api):
    pid = new_project(api)
    sid = scan_snippet(api, pid)
    r = api.post(f"/api/v1/scans/{sid}/cancel")
    assert r.status_code == 202 and r.get_json()["status"] == "canceled"
    assert api.post(f"/api/v1/scans/{sid}/cancel").status_code == 409


def test_report_formats(ready):
    api, _, sid = ready
    r = api.get(f"/api/v1/scans/{sid}/report?format=sarif")
    assert r.status_code == 200 and "attachment" in r.headers["Content-Disposition"]
    sarif = json.loads(r.get_data(as_text=True))
    assert sarif["version"] == "2.1.0"
    res = sarif["runs"][0]["results"]
    assert res and all(x["baselineState"] == "new" and x["partialFingerprints"]["sastStudio/v1"] for x in res)
    assert sarif["runs"][0]["automationDetails"]["id"].startswith("sast-studio/default/")
    html = api.get(f"/api/v1/scans/{sid}/report?format=html")
    assert html.status_code == 200 and html.mimetype == "text/html"
    js = api.get(f"/api/v1/scans/{sid}/report?format=json").get_json()
    assert js["scan"]["id"] == sid and js["findings"]
    assert api.get(f"/api/v1/scans/{sid}/report?format=pdf").status_code == 400


def test_report_requires_finished_scan(api):
    pid = new_project(api)
    sid = scan_snippet(api, pid)
    assert api.get(f"/api/v1/scans/{sid}/report").status_code == 409


def test_diff_and_baseline_state(ready):
    api, pid, sid1 = ready
    sid2 = scan_snippet(api, pid, VULN.replace("pickle.loads(blob)", "json.loads(blob)") + "\nimport random\nrandom.random()\n")
    drain()
    d = api.get(f"/api/v1/scans/{sid2}/diff").get_json()
    assert d["base_scan_id"] == sid1
    assert [f["rule_id"] for f in d["new"]] == ["py/insecure-random"]
    assert [f["rule_id"] for f in d["fixed"]] == ["py/insecure-deserialization"]
    sarif = json.loads(api.get(f"/api/v1/scans/{sid2}/report?format=sarif").get_data(as_text=True))
    states = {r["ruleId"]: r["baselineState"] for r in sarif["runs"][0]["results"]}
    assert states["py/insecure-random"] == "new"
    assert states["py/weak-hash"] == "unchanged"
    assert states["py/insecure-deserialization"] == "absent"
    explicit = api.get(f"/api/v1/scans/{sid2}/diff?base={sid1}").get_json()
    assert explicit["persisting_count"] == d["persisting_count"]


def test_diff_rejects_different_streams(api):
    pid = new_project(api)
    a = scan_snippet(api, pid, category="main")
    b = scan_snippet(api, pid, category="otra")
    drain()
    assert api.get(f"/api/v1/scans/{b}/diff?base={a}").status_code == 422


# --- Issues --------------------------------------------------------------------------------------------

def test_issues_triage_events_and_comments(ready):
    api, pid, _ = ready
    issues = api.get(f"/api/v1/projects/{pid}/issues?lifecycle=open").get_json()["items"]
    weak = next(i for i in issues if i["rule_id"] == "py/weak-hash")
    detail = api.get(f"/api/v1/issues/{weak['id']}").get_json()
    assert detail["rule"]["id"] == "py/weak-hash" and detail["last_occurrence"]["path"] == "app.py"
    assert api.patch(f"/api/v1/issues/{weak['id']}", json={"triage": "false_positive"}).status_code == 422
    assert api.patch(f"/api/v1/issues/{weak['id']}", json={"triage": "bogus"}).status_code == 400
    r = api.patch(f"/api/v1/issues/{weak['id']}", json={"triage": "false_positive", "justification": "ETag"})
    assert r.status_code == 200 and r.get_json()["triage"] == "false_positive"
    assert api.post(f"/api/v1/issues/{weak['id']}/comments", json={"body": "Revisado en clase"}).status_code == 201
    assert api.post(f"/api/v1/issues/{weak['id']}/comments", json={"body": ""}).status_code == 400
    events = api.get(f"/api/v1/issues/{weak['id']}/events").get_json()
    assert [e["kind"] for e in events] == ["lifecycle", "triage", "comment"]
    assert events[1]["to"] == "false_positive" and events[1]["user"]["name"] == "ana"
    fp = api.get(f"/api/v1/projects/{pid}/issues?triage=false_positive").get_json()["items"]
    assert [i["id"] for i in fp] == [weak["id"]]


def test_metrics_endpoint(ready):
    api, pid, _ = ready
    scan_snippet(api, pid, VULN.replace("hashlib.md5(data)", "hashlib.sha256(data)"))
    drain()
    m = api.get(f"/api/v1/projects/{pid}/metrics").get_json()
    assert len(m["open_by_severity"]) == 2 and m["new_vs_fixed"][1]["fixed"] == 1
    assert "medium" in m["mttr_days"] and m["density_per_kloc"] is not None
    assert api.get(f"/api/v1/projects/{pid}/metrics?from=ayer").status_code == 400


# --- Rutas antiguas ----------------------------------------------------------------------------------------

def test_legacy_alias_redirects(api):
    r = api.get("/api/rules?language=python")
    assert r.status_code == 308 and r.headers["Location"].endswith("/api/v1/rules?language=python")


# --- BOLA: el usuario B recibe 404 con los IDs de A en TODOS los endpoints ---------------------------------

def _resources_of_a(app):
    a = login(app.test_client(), "a@example.com")
    pid = new_project(a)
    sid = scan_snippet(a, pid)
    drain()
    iid = a.get(f"/api/v1/projects/{pid}/issues").get_json()["items"][0]["id"]
    return {"pid": pid, "sid": sid, "iid": iid}


BOLA_CALLS = [
    ("get", "/api/v1/projects/{pid}", None),
    ("patch", "/api/v1/projects/{pid}", {"name": "robado"}),
    ("delete", "/api/v1/projects/{pid}", None),
    ("post", "/api/v1/projects/{pid}/scans", {"source": "snippet", "filename": "a.py", "code": "x=1"}),
    ("get", "/api/v1/projects/{pid}/scans", None),
    ("get", "/api/v1/projects/{pid}/issues", None),
    ("get", "/api/v1/projects/{pid}/metrics", None),
    ("get", "/api/v1/scans/{sid}", None),
    ("post", "/api/v1/scans/{sid}/cancel", None),
    ("get", "/api/v1/scans/{sid}/findings", None),
    ("get", "/api/v1/scans/{sid}/diff", None),
    ("get", "/api/v1/scans/{sid}/report", None),
    ("get", "/api/v1/issues/{iid}", None),
    ("patch", "/api/v1/issues/{iid}", {"triage": "confirmed"}),
    ("get", "/api/v1/issues/{iid}/events", None),
    ("post", "/api/v1/issues/{iid}/comments", {"body": "hola"}),
]


@pytest.mark.parametrize("method, url, body", BOLA_CALLS, ids=[f"{m.upper()} {u}" for m, u, _ in BOLA_CALLS])
def test_bola_other_user_gets_404(app, method, url, body):
    ids = _resources_of_a(app)
    b = login(app.test_client(), "b@example.com")
    kwargs = {"json": body} if body is not None else {}
    r = getattr(b, method)(url.format(**ids), **kwargs)
    assert r.status_code == 404, (url, r.status_code)
    assert r.get_json()["error"]["code"] == "not_found"


def test_bola_listing_only_shows_own_projects(app):
    _resources_of_a(app)
    b = login(app.test_client(), "b@example.com")
    assert b.get("/api/v1/projects").get_json()["items"] == []


@pytest.mark.parametrize("bad", ["no-es-uuid", "00000000-0000-0000-0000-000000000000"])
def test_invalid_or_unknown_ids_are_404(api, bad):
    assert api.get(f"/api/v1/projects/{bad}").status_code == 404
    assert api.get(f"/api/v1/scans/{bad}").status_code == 404
    assert api.get(f"/api/v1/issues/{bad}").status_code == 404


def test_every_api_route_is_covered_by_bola_or_public(app):
    public = {"/api/v1/auth/login", "/api/v1/auth/callback", "/api/v1/auth/dev-login", "/api/v1/auth/logout",
              "/api/v1/auth/me", "/api/v1/config", "/api/v1/rules", "/api/v1/rules/<path:rule_id>",
              "/api/v1/projects",
              # Retos: el catálogo es común y el intento se busca por el usuario de la sesión, nunca por un ID
              # ajeno (lo prueba test_challenges.py::test_attempts_are_private).
              "/api/v1/challenges", "/api/v1/challenges/<challenge_id>", "/api/v1/challenges/<challenge_id>/attempt",
              "/api/v1/challenges/<challenge_id>/submissions",
              # Uso: datos agregados de todo el sistema, solo para administradores (test_usage.py).
              "/api/v1/usage",
              "/api/<path:rest>"}
    covered = {u.replace("{pid}", "<project_id>").replace("{sid}", "<scan_id>").replace("{iid}", "<issue_id>")
               for _, u, _ in BOLA_CALLS}
    routes = {r.rule for r in app.url_map.iter_rules() if r.rule.startswith("/api/")}
    assert routes - public - covered == set()
    db.session.remove()
