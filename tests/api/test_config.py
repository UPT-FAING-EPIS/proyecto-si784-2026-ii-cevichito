"""F7: /api/v1/config da a la interfaz los métodos de acceso y los límites, sin secretos."""

from __future__ import annotations

import json

from .conftest import make_settings


def test_config_is_public_and_lists_limits(client):
    r = client.get("/api/v1/config")
    assert r.status_code == 200
    body = r.get_json()
    assert body["auth"] == {"oidc": False, "google": False, "provider": "Google", "dev_login": True}
    assert body["limits"]["max_upload_mb"] == 25
    assert body["limits"]["max_compression_ratio"] == 100
    assert body["version"]
    assert r.headers["Content-Security-Policy"].startswith("default-src 'none'")


def test_config_reports_google_and_hides_secrets(app, client):
    app.config["SETTINGS"] = make_settings(google_client_id="cliente-123.apps.googleusercontent.com",
                                           google_client_secret="secreto-de-prueba")
    r = client.get("/api/v1/config")
    assert r.get_json()["auth"]["google"] is True
    raw = json.dumps(r.get_json())
    assert "cliente-123" not in raw and "secreto" not in raw


def test_public_origin_falls_back_to_render_external_url(monkeypatch):
    from api.settings import Settings

    base = dict(_env_file=None, environment="test", secret_key="k" * 40, session_hmac_key="h" * 40,
                database_url="sqlite://")
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://sast-studio.onrender.com")
    assert Settings(**base).public_origin == "https://sast-studio.onrender.com"
    monkeypatch.setenv("PUBLIC_ORIGIN", "https://sast.universidad.edu")  # un dominio propio manda
    assert Settings(**base).public_origin == "https://sast.universidad.edu"
