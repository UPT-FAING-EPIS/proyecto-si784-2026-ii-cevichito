"""Dashboard de uso: solo administradores y cifras coherentes con lo que pasó."""

from __future__ import annotations

from .conftest import login, make_settings
from .test_contract import drain, new_project, scan_snippet

URL = "/api/v1/usage"


def test_usage_requires_admin(app):
    api = login(app.test_client(), "ana@example.com")
    assert api.get("/api/v1/auth/me").get_json()["is_admin"] is False
    r = api.get(URL)
    assert r.status_code == 403 and r.get_json()["error"]["code"] == "forbidden"


def test_usage_requires_session(client):
    assert client.get(URL, base_url="https://sast.test").status_code == 401


def test_usage_counts_activity(app):
    app.config["SETTINGS"] = make_settings(admin_emails="jefa@example.com")
    alumno = login(app.test_client(), "ana@example.com")
    pid = new_project(alumno)
    scan_snippet(alumno, pid)
    scan_snippet(alumno, pid)
    drain()
    admin = login(app.test_client(), "Jefa@Example.com")
    assert admin.get("/api/v1/auth/me").get_json()["is_admin"] is True
    data = admin.get(URL + "?days=7").get_json()
    t = data["totals"]
    assert t["users"] == 2 and t["active_users"] == 2 and t["new_users"] == 2
    assert t["projects"] == 1 and t["scans"] == 2 and t["findings"] > 0
    assert t["scan_seconds_median"] is not None and t["failure_rate"] == 0
    assert data["by_status"] == {"done": 2} and data["by_source"] == {"snippet": 2}
    assert len(data["daily"]) in (7, 8) and sum(d["scans"] for d in data["daily"]) == 2
    assert data["top_rules"][0]["count"] >= 2
    assert len(data["challenges"]) >= 8


def test_usage_rejects_bad_days(app):
    app.config["SETTINGS"] = make_settings(admin_emails="jefa@example.com")
    admin = login(app.test_client(), "jefa@example.com")
    assert admin.get(URL + "?days=muchos").status_code == 400
    assert admin.get(URL + "?days=9999").get_json()["days"] == 365
