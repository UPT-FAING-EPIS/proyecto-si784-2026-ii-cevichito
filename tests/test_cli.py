"""Pruebas de la CLI `sast` (mismo motor que la API)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from sast.cli import main

CASES = Path(__file__).parent / "rules" / "cases"


def test_scan_json_and_sarif(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(main, ["scan", str(target), "-f", "json"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data["findings"][0]["rule_id"] == "py/weak-hash"
    out = tmp_path / "r.sarif"
    res = runner.invoke(main, ["scan", str(target), "-f", "sarif", "-o", str(out)])
    assert res.exit_code == 0
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["partialFingerprints"]["sastStudio/v1"]


def test_severity_threshold_exit_code(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("import pickle\npickle.loads(b'')\n", encoding="utf-8")
    res = CliRunner().invoke(main, ["scan", str(target), "--severity-threshold", "high"])
    assert res.exit_code == 1


def test_rules_and_test_rules_commands():
    runner = CliRunner()
    res = runner.invoke(main, ["rules", "--format", "json"])
    assert res.exit_code == 0 and len(json.loads(res.output)) >= 12
    res = runner.invoke(main, ["test-rules", str(CASES)])
    assert res.exit_code == 0, res.output
    assert "Todos los casos pasan" in res.output
