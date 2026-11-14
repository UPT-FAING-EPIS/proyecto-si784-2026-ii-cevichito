"""Pruebas unitarias del motor (F1/F2): contrato, runner, supresiones, huellas y taint."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from sast.engine.fingerprint import assign_fingerprints, normalize_path
from sast.engine.runner import Engine, EngineConfig, ScanCanceled
from sast.reports import render_html, to_sarif
from sast.rules.api import Confidence, PythonRule, RuleMeta, Severity
from sast.rules.registry import RuleSet, build_ruleset, default_ruleset, load_plugins, register
from sast.rules.yaml_rules import load_yaml_file
from sast.testing import covered_rule_ids

CASES = Path(__file__).resolve().parents[1] / "rules" / "cases"


def _meta(rule_id: str, **kw) -> RuleMeta:
    base = dict(id=rule_id, name=rule_id, message="m", severity=Severity.HIGH, confidence=Confidence.HIGH,
                languages=("python",), explanation="e", remediation="r", example_bad="b", example_good="g")
    base.update(kw)
    return RuleMeta(**base)


def scan(code: str, path: str = "app.py", ruleset: RuleSet | None = None, **cfg):
    return Engine(ruleset, EngineConfig(**cfg)).scan_source(code, path)


def ids(report) -> list[tuple[str, int]]:
    return [(f.rule_id, f.line) for f in report.findings if not f.suppressed]


# --- Catálogo -----------------------------------------------------------------

def test_catalog_metadata_is_complete():
    rs = default_ruleset()
    assert len(rs) >= 12
    assert not rs.load_errors
    for m in rs.metas():
        assert m.cwe and m.owasp, m.id
        for field in ("explanation", "remediation", "example_bad", "example_good"):
            assert getattr(m, field).strip(), f"{m.id} sin {field}"


def test_every_rule_has_a_positive_case():
    missing = set(default_ruleset().ids) - covered_rule_ids(CASES)
    assert not missing, f"reglas sin caso # ruleid: {sorted(missing)}"


def test_duplicate_rule_ids_are_rejected(monkeypatch):
    monkeypatch.setattr("sast.rules.registry._BUILTIN_CLASSES", {})
    class A(PythonRule):
        meta = _meta("t/dup")

    class B(PythonRule):
        meta = _meta("t/dup")

    with pytest.raises(ValueError):
        RuleSet((A(), B()))
    register(A)
    with pytest.raises(ValueError):
        register(B)


def test_rule_meta_validates_id():
    with pytest.raises(ValueError):
        _meta("sin-prefijo")


# --- RF-07: un hallazgo por ubicación ----------------------------------------------

def test_md5_produces_exactly_one_finding():
    r = scan("import hashlib\nh = hashlib.md5(b'x').hexdigest()\n")
    weak = [f for f in r.findings if f.rule_id == "py/weak-hash"]
    assert len(weak) == 1 and weak[0].variant == "md5"
    assert len({(f.rule_id, f.line) for f in r.findings}) == len(r.findings)


def test_md5_non_security_use_is_not_reported():
    r = scan("import hashlib\nh = hashlib.md5(b'x', usedforsecurity=False)\n")
    assert ("py/weak-hash", 2) not in ids(r)


# --- RF-08: errores de reglas visibles ----------------------------------------------

def test_failing_rule_is_reported_and_does_not_hide_others():
    class Boom(PythonRule):
        node_types = (ast.Call,)
        meta = _meta("t/boom")

        def check(self, ctx, node):
            raise RuntimeError("fallo a propósito")

    rs = RuleSet((Boom(), *default_ruleset().select(ids=["py/weak-hash"])))
    r = scan("import hashlib\nhashlib.md5(b'x')\nhashlib.sha1(b'y')\n", ruleset=rs)
    assert [e.rule_id for e in r.rule_errors] == ["t/boom"]  # una vez por archivo, no por nodo
    assert r.rule_errors[0].exc_type == "RuntimeError"
    assert len([f for f in r.findings if f.rule_id == "py/weak-hash"]) == 2
    sarif = to_sarif(r, rs.metas())
    notes = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert notes and "t/boom" in notes[0]["message"]["text"]


# --- RF-06: supresiones ---------------------------------------------------------------

@pytest.mark.parametrize("comment", [
    "# sast: ignore[py/weak-hash] reason: checksum",
    "# nosec B324",
    "# nosec",
    "# sast: ignore",
])
def test_inline_suppression_marks_but_keeps(comment):
    r = scan(f"import hashlib\nh = hashlib.md5(b'x')  {comment}\n")
    weak = [f for f in r.findings if f.rule_id == "py/weak-hash"]
    assert len(weak) == 1 and weak[0].suppressed
    assert r.summary["suppressed"] == 1


def test_suppression_on_previous_comment_line():
    r = scan("import hashlib\n# sast: ignore[py/weak-hash] reason: etag\nh = hashlib.md5(b'x')\n")
    assert [f.suppressed for f in r.findings if f.rule_id == "py/weak-hash"] == [True]


def test_suppression_for_other_rule_does_not_apply():
    r = scan("import hashlib\nh = hashlib.md5(b'x')  # sast: ignore[py/xss]\n")
    assert [f.suppressed for f in r.findings if f.rule_id == "py/weak-hash"] == [False]


def test_suppressed_findings_go_to_sarif_suppressions():
    r = scan("import hashlib\nh = hashlib.md5(b'x')  # nosec\n")
    res = to_sarif(r, default_ruleset().metas())["runs"][0]["results"]
    assert res[0]["suppressions"][0]["kind"] == "inSource"


# --- supersedes ----------------------------------------------------------------------

def test_supersedes_hides_generic_rule_on_same_line():
    class Generic(PythonRule):
        node_types = (ast.Call,)
        meta = _meta("t/generic")

        def check(self, ctx, node):
            yield self.finding(ctx, node)

    class Specific(PythonRule):
        node_types = (ast.Call,)
        meta = _meta("t/specific", supersedes=("t/generic",))

        def check(self, ctx, node):
            if ctx.qualname(node) == "os.system":
                yield self.finding(ctx, node)

    r = scan("import os\nos.system('x')\nprint(1)\n", ruleset=RuleSet((Generic(), Specific())))
    assert ("t/specific", 2) in ids(r)
    assert ("t/generic", 2) not in ids(r)
    assert ("t/generic", 3) in ids(r)


# --- RF-04 / RF-05: YAML y plugins ------------------------------------------------------

def test_yaml_rule_loads_without_touching_engine(tmp_path):
    (tmp_path / "custom.yaml").write_text("""
rules:
  - id: py/no-print
    name: Uso de print
    message: "Se usa print"
    severity: LOW
    confidence: HIGH
    languages: [python]
    engine: ast
    docs: {explanation: e, remediation: r, example_bad: b, example_good: g}
    match: { call: "print" }
""", encoding="utf-8")
    rs = build_ruleset([tmp_path], plugins=False)
    assert "py/no-print" in rs.ids
    assert ("py/no-print", 1) in ids(scan("print('hola')\n", ruleset=rs))


def test_invalid_yaml_rule_is_a_load_error(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - id: py/x\n    engine: ast\n", encoding="utf-8")
    rules, errors = load_yaml_file(bad)
    assert not rules and errors and "bad.yaml" in errors[0].source


def test_plugins_load_from_entry_points(monkeypatch):
    class Plugin(PythonRule):
        node_types = ()
        meta = _meta("ext/demo")

        def check(self, ctx, node):
            yield self.finding(ctx, line=1)

    class EP:
        def __init__(self, name, obj):
            self.name, self._obj = name, obj

        def load(self):
            if isinstance(self._obj, Exception):
                raise self._obj
            return self._obj

    monkeypatch.setattr("sast.rules.registry.entry_points",
                        lambda group: [EP("ok", Plugin), EP("roto", ImportError("no existe"))])
    rules, errors = load_plugins()
    assert [r.meta.id for r in rules] == ["ext/demo"]
    assert errors and errors[0].source == "plugin:roto"


# --- Huellas ---------------------------------------------------------------------------

def test_fingerprint_survives_line_shift():
    code = "import hashlib\nh = hashlib.md5(b'x')\n"
    a = scan(code).findings[0].fingerprint
    b = scan("\n" * 20 + code).findings[0].fingerprint
    assert a == b and len(a) == 64


def test_fingerprint_distinguishes_repeated_code():
    r = scan("import hashlib\nhashlib.md5(b'x')\nhashlib.md5(b'x')\n")
    fps = [f.fingerprint for f in r.findings if f.rule_id == "py/weak-hash"]
    assert len(fps) == 2 and len(set(fps)) == 2


def test_fingerprint_ignores_zipball_prefix():
    assert normalize_path("owner-repo-1a2b3c4/src/app.py") == "src/app.py"
    assert normalize_path("./src\\app.py") == "src/app.py"


def test_scan_is_deterministic():
    code = (CASES / "py-command-injection.py").read_text(encoding="utf-8")
    a = to_sarif(scan(code), default_ruleset().metas())
    b = to_sarif(scan(code), default_ruleset().metas())
    assert json.dumps(a["runs"][0]["results"], sort_keys=True) == json.dumps(b["runs"][0]["results"], sort_keys=True)


def test_assign_fingerprints_is_order_independent():
    r = scan("import hashlib\nhashlib.md5(b'a')\nhashlib.sha1(b'b')\n")
    lines = {"app.py": r.sources["app.py"].splitlines()}
    assert {f.fingerprint for f in assign_fingerprints(reversed(r.findings), lines)} == {f.fingerprint for f in r.findings}


# --- RF-09: taint entre funciones ---------------------------------------------------------

INTERPROC = '''
import os
from flask import request

def helper(v):
    os.system("ping " + v)

def view():
    host = request.args.get("h")
    helper(host)
'''


def test_interprocedural_command_injection_has_trace():
    r = scan(INTERPROC)
    f = next(f for f in r.findings if f.rule_id == "py/command-injection")
    assert f.line == 6 and f.variant == "interprocedural"
    assert len(f.trace) >= 3
    lines = [s.line for s in f.trace]
    assert lines[0] == 9 and 10 in lines and lines[-1] == 6


def test_sanitizer_inside_callee_stops_flow():
    code = INTERPROC.replace('os.system("ping " + v)', 'os.system("ping " + shlex.quote(v))').replace("import os", "import os, shlex")
    r = scan(code)
    assert not [f for f in r.findings if f.rule_id == "py/command-injection" and f.confidence >= Confidence.MEDIUM]


def test_taint_through_return_value():
    code = '''
import os
from flask import request

def leer():
    return request.args.get("c")

def run():
    os.system(leer())
'''
    assert ("py/command-injection", 9) in ids(scan(code))


def test_recursive_functions_terminate():
    code = '''
from flask import request
import os

def a(x, n):
    if n:
        return b(x, n - 1)
    os.system(x)

def b(x, n):
    return a(x, n)

def view():
    a(request.args.get("q"), 3)
'''
    assert ("py/command-injection", 8) in ids(scan(code))


# --- RF-10: secretos como argumento -----------------------------------------------------------

def test_env_default_secret_and_password_argument():
    code = '''
import os
SECRET = os.environ.get("JWT_SECRET", "sast-studio-dev-session-secret")
pw = _demo_pw("Admin123!")
ok = os.environ.get("JWT_SECRET")
'''
    found = ids(scan(code))
    assert ("generic/hardcoded-secret", 3) in found
    assert ("generic/hardcoded-secret", 4) in found
    assert ("generic/hardcoded-secret", 5) not in found


# --- Runner ------------------------------------------------------------------------------

def test_filters_and_cancellation(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import random\nrandom.random()\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("eval('1')\n", encoding="utf-8")
    full = Engine().scan_path(tmp_path)
    assert full.files_scanned == 2  # los tests se excluyen por defecto
    high = Engine(config=EngineConfig(min_confidence=Confidence.MEDIUM)).scan_path(tmp_path)
    assert "py/insecure-random" not in {f.rule_id for f in high.findings}
    progress = []
    Engine().scan_path(tmp_path, progress=lambda done, total: progress.append((done, total)))
    assert progress[-1] == (2, 2)
    with pytest.raises(ScanCanceled):
        Engine().scan_path(tmp_path, should_cancel=lambda: True)


def test_heuristic_rules_do_not_run_on_python():
    r = scan("import os\nos.system('ls')\n")
    assert not [f for f in r.findings if f.rule_id.startswith("multi/")]


def test_syntax_error_does_not_crash():
    r = scan("def broken(:\n  pass\nPASSWORD = 'Sup3r-Secr3t!'\n")
    assert r.files_scanned == 1 and not r.rule_errors
    assert ("generic/hardcoded-secret", 3) in ids(r)


def test_html_report_escapes_content():
    r = scan("PASSWORD = '<script>alert(1)</script>'\n")
    html = render_html(r, default_ruleset().metas())
    assert "<script>alert(1)</script>" not in html
