"""Instantánea normalizada (sin fechas ni duraciones) del escaneo de `samples/`."""

from __future__ import annotations

from pathlib import Path

from sast.engine.runner import Engine, EngineConfig

ROOT = Path(__file__).resolve().parents[2]


def snapshot() -> list[dict]:
    report = Engine(config=EngineConfig(exclude_tests=False)).scan_path(ROOT / "samples")
    rows = [
        {"rule_id": f.rule_id, "path": f.path, "line": f.line, "severity": f.severity.label,
         "variant": f.variant, "fingerprint": f.fingerprint}
        for f in report.findings
    ]
    return sorted(rows, key=lambda r: (r["path"], r["line"], r["rule_id"]))
