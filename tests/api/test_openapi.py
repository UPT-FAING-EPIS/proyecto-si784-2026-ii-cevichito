"""El contrato OpenAPI es válido y cubre todas las rutas registradas."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

SPEC = Path(__file__).resolve().parents[2] / "docs" / "api" / "openapi.yaml"


def test_openapi_is_valid():
    validator = pytest.importorskip("openapi_spec_validator")
    validator.validate(yaml.safe_load(SPEC.read_text(encoding="utf-8")))


def test_openapi_documents_every_route(app):
    documented = set(yaml.safe_load(SPEC.read_text(encoding="utf-8"))["paths"])
    routes = set()
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith(("/api/v1/", "/healthz", "/readyz")):
            routes.add(re.sub(r"<(?:path:)?(\w+)>", r"{\1}", rule.rule))
    assert routes - documented == set()
