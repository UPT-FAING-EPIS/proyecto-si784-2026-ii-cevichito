"""F3: configuración, emparejado de issues, ciclo de vida, diff y métricas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy import select, text

from api.extensions import db
from api.models.entities import Issue, IssueEvent, Occurrence, Scan, utcnow
from api.services import issue_service, metrics_service
from sast.engine.runner import Engine
from sast.rules.registry import default_ruleset

from .conftest import PG_URL, make_settings

VULN = '''import hashlib
import pickle

def firma(data):
    return hashlib.md5(data).hexdigest()

def cargar(blob):
    return pickle.loads(blob)
'''


def run_scan(project, files: dict[str, str], *, source="zip", rules=None, category="default") -> Scan:
    ruleset = default_ruleset() if rules is None else default_ruleset().select(ids=rules)
    report = Engine(ruleset).scan_files(list(files.items()))
    scan = Scan(project_id=project.id, source=source, category=category, status="running",
                rules_enabled=ruleset.ids, started_at=utcnow())
    db.session.add(scan)
    db.session.flush()
    issue_service.ingest(scan, report, ruleset)
    scan.status, scan.finished_at, scan.loc_total = "done", utcnow(), report.loc_total
    db.session.commit()
    return scan


def issues(project, rule=None) -> list[Issue]:
    q = select(Issue).where(Issue.project_id == project.id)
    if rule:
        q = q.where(Issue.rule_id == rule)
    return list(db.session.scalars(q))


# --- Configuración (RNF-01) ------------------------------------------------------------

def test_settings_fail_without_secrets(monkeypatch):
    for var in ("SECRET_KEY", "SESSION_HMAC_KEY", "DATABASE_URL"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ValidationError):
        from api.settings import Settings

        Settings(_env_file=None)


def test_settings_reject_short_secret():
    with pytest.raises(ValidationError):
        make_settings(secret_key="corto")


def test_dev_login_forbidden_in_prod():
    with pytest.raises(ValidationError):
        make_settings(environment="prod", dev_login_enabled=True, google_client_id="x", google_client_secret="y",
                      database_url="postgresql://u:p@h/db")


def test_prod_requires_google_and_postgres():
    with pytest.raises(ValidationError):
        make_settings(environment="prod", dev_login_enabled=False, database_url="postgresql://u:p@h/db")
    with pytest.raises(ValidationError):
        make_settings(environment="prod", dev_login_enabled=False, google_client_id="x", google_client_secret="y",
                      database_url="sqlite://")


def test_database_url_normalized_to_psycopg():
    s = make_settings(database_url="postgres://u:p@h:5432/db")
    assert s.database_url.startswith("postgresql+psycopg://")


# --- Emparejado y ciclo de vida (RF-15) -------------------------------------------------

def test_first_scan_creates_open_issues(project):
    scan = run_scan(project, {"app.py": VULN})
    found = issues(project)
    assert {i.rule_id for i in found} == {"py/weak-hash", "py/insecure-deserialization"}
    assert all(i.lifecycle == "open" for i in found)
    assert scan.summary["new"] == 2 and scan.summary["fixed"] == 0
    assert {o.change for o in db.session.scalars(select(Occurrence))} == {"new"}


def test_moving_code_does_not_duplicate_issues(project):
    run_scan(project, {"app.py": VULN})
    scan2 = run_scan(project, {"app.py": "\n" * 20 + VULN})
    assert len(issues(project)) == 2
    assert scan2.summary["persisting"] == 2 and scan2.summary["new"] == 0
    assert issues(project, "py/weak-hash")[0].current_line == 25


def test_removed_finding_becomes_fixed_and_returns_reopened(project):
    run_scan(project, {"app.py": VULN})
    fixed_code = VULN.replace("hashlib.md5(data)", "hashlib.sha256(data)")
    s2 = run_scan(project, {"app.py": fixed_code})
    weak = issues(project, "py/weak-hash")[0]
    assert weak.lifecycle == "fixed" and weak.fixed_at is not None and s2.summary["fixed"] == 1
    s3 = run_scan(project, {"app.py": VULN})
    db.session.refresh(weak)
    assert weak.lifecycle == "reopened" and weak.reopened_count == 1 and s3.summary["reopened"] == 1
    kinds = [(e.from_state, e.to_state) for e in db.session.scalars(
        select(IssueEvent).where(IssueEvent.issue_id == weak.id).order_by(IssueEvent.id))]
    assert kinds == [(None, "open"), ("open", "fixed"), ("fixed", "reopened")]


def test_false_positive_triage_survives_rescans(project, user):
    run_scan(project, {"app.py": VULN})
    weak = issues(project, "py/weak-hash")[0]
    issue_service.set_triage(weak, "false_positive", "Es una ETag, no seguridad", user.id)
    db.session.commit()
    run_scan(project, {"app.py": VULN.replace("hashlib.md5(data)", "hashlib.sha256(data)")})
    run_scan(project, {"app.py": VULN})
    db.session.refresh(weak)
    assert weak.triage == "false_positive"
    assert weak.lifecycle == "open" and weak.reopened_count == 0


def test_triage_requires_justification(project, user):
    run_scan(project, {"app.py": VULN})
    with pytest.raises(ValueError):
        issue_service.set_triage(issues(project)[0], "accepted", "  ", user.id)


def test_disabling_a_rule_does_not_count_as_fixed(project):
    run_scan(project, {"app.py": VULN})
    run_scan(project, {"app.py": VULN}, rules=["py/insecure-deserialization"])
    assert issues(project, "py/weak-hash")[0].lifecycle == "open"


def test_snippet_scan_only_fixes_files_in_scope(project):
    run_scan(project, {"a.py": VULN, "b.py": VULN}, source="zip")
    run_scan(project, {"a.py": "x = 1\n"}, source="snippet")
    by_path = {(i.current_path, i.lifecycle) for i in issues(project, "py/weak-hash")}
    assert by_path == {("a.py", "fixed"), ("b.py", "open")}


def test_renamed_file_keeps_issue(project):
    run_scan(project, {"old/app.py": VULN})
    s2 = run_scan(project, {"new/app.py": VULN})
    assert len(issues(project)) == 2
    assert {i.current_path for i in issues(project)} == {"new/app.py"}
    assert s2.summary["new"] == 0


def test_categories_are_separate_streams(project):
    run_scan(project, {"app.py": VULN}, category="main")
    run_scan(project, {"app.py": "x = 1\n"}, category="feature")
    assert all(i.lifecycle == "open" for i in issues(project) if i.category == "main")


def test_secret_snippets_are_redacted(project):
    run_scan(project, {"cfg.py": 'API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"\n'})
    occ = db.session.scalars(select(Occurrence)).first()
    assert "sk-abc" not in occ.snippet and "•••" in occ.snippet


# --- Diff y métricas (RF-17, RF-18) ---------------------------------------------------------

def test_diff_between_scans(project):
    s1 = run_scan(project, {"app.py": VULN})
    s2 = run_scan(project, {"app.py": VULN.replace("pickle.loads(blob)", "json.loads(blob)")
                            + "\nimport random\nrandom.random()\n"})
    assert s2.baseline_scan_id == s1.id
    d = metrics_service.scan_diff(s2, s1)
    assert [o.issue.rule_id for o in d["new"]] == ["py/insecure-random"]
    assert [o.issue.rule_id for o in d["fixed"]] == ["py/insecure-deserialization"]
    assert d["persisting_count"] == 1
    assert s2.summary["new"] == len(d["new"]) and s2.summary["fixed"] == len(d["fixed"])


def test_metrics_series_and_mttr(project):
    run_scan(project, {"app.py": VULN})
    run_scan(project, {"app.py": VULN.replace("hashlib.md5(data)", "hashlib.sha256(data)")})
    m = metrics_service.project_metrics(project.id)
    assert len(m["open_by_severity"]) == 2
    assert m["open_by_severity"][0]["critical"] == 1 and m["open_by_severity"][0]["medium"] == 1
    assert m["new_vs_fixed"][1]["fixed"] == 1
    assert m["mttr_days"]["medium"]["count"] == 1
    assert m["open_issues"] == 1 and m["density_per_kloc"] is not None


def test_project_delete_cascades(project):
    run_scan(project, {"app.py": VULN})
    db.session.delete(project)
    db.session.commit()
    assert db.session.scalar(select(Issue).limit(1)) is None
    assert db.session.scalar(select(Occurrence).limit(1)) is None


# --- Salud y PostgreSQL ----------------------------------------------------------------------

def test_healthz_and_readyz(client):
    assert client.get("/healthz").get_json() == {"status": "ok"}
    r = client.get("/readyz")
    if PG_URL:
        assert r.status_code == 200 and r.get_json()["migrations"] == "head"
    else:  # con SQLite + create_all no hay tabla alembic_version
        assert r.status_code == 503 and r.get_json()["db"] == "ok"


@pytest.mark.skipif(not PG_URL, reason="requiere PostgreSQL")
def test_audit_log_is_append_only(app):
    db.session.execute(text("INSERT INTO audit_log (at, event, outcome, details) VALUES (now(), 'x', 'success', '{}')"))
    db.session.commit()
    with pytest.raises(Exception):
        db.session.execute(text("DELETE FROM audit_log"))
        db.session.commit()
    db.session.rollback()
