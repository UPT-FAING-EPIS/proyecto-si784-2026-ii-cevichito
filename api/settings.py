"""Configuración 12-factor (RNF-01): todo viene del entorno y los secretos no tienen valor por defecto.

Si falta un secreto obligatorio o mide menos de 32 bytes, `Settings()` lanza
`ValidationError` y la aplicación no arranca.
"""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_SECRET_BYTES = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore",
                                      secrets_dir=None, case_sensitive=False)

    environment: Literal["dev", "test", "prod"] = "prod"

    # --- Secretos obligatorios (sin valor por defecto) ---------------------------
    secret_key: SecretStr
    session_hmac_key: SecretStr
    database_url: str

    # --- Google OIDC (obligatorio salvo con login de desarrollo) ------------------
    google_client_id: str | None = Field(default=None, validation_alias=AliasChoices("oidc_client_id", "google_client_id"))
    google_client_secret: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("oidc_client_secret", "google_client_secret"))
    oauth_redirect_uri: str | None = None
    google_hosted_domain: str | None = None
    # Otro proveedor OIDC (Microsoft Entra, Keycloak, el de la universidad...). Si se define,
    # los endpoints se leen de <issuer>/.well-known/openid-configuration y GOOGLE_CLIENT_ID /
    # GOOGLE_CLIENT_SECRET (o sus alias OIDC_CLIENT_ID / OIDC_CLIENT_SECRET) son los de ese proveedor.
    oidc_issuer: str | None = None
    oidc_provider_name: str | None = None            # texto del botón; por defecto "Google"

    # --- Acceso de desarrollo (RF-22) ---------------------------------------------
    dev_login_enabled: bool = False

    # --- Web ------------------------------------------------------------------------
    # Origen único de la SPA y la API (mismo sitio). En Render, si no se define, se usa la
    # URL pública que la plataforma pone en RENDER_EXTERNAL_URL (https://<servicio>.onrender.com).
    public_origin: str = Field(default="http://localhost:8080",
                               validation_alias=AliasChoices("public_origin", "render_external_url"))
    extra_allowed_origins: list[str] = Field(default_factory=list)
    # Emails que ven el dashboard de uso (/uso), separados por comas. Vacío: nadie.
    admin_emails: str = ""
    trust_proxy: bool = False
    proxy_hops: int = 1                              # cuántos proxies hay delante (X-Forwarded-*)
    spa_dir: str | None = None                       # si se define, Flask sirve la SPA compilada (mismo origen)

    # --- Sesión ---------------------------------------------------------------------
    session_idle_minutes: int = 120
    session_absolute_hours: int = 12

    # --- Límites --------------------------------------------------------------------
    max_upload_mb: int = 25
    max_snippet_kb: int = 1024
    max_zip_entries: int = 10_000
    max_entry_mb: int = 10
    max_total_uncompressed_mb: int = 200
    max_compression_ratio: int = 100
    scan_timeout_s: int = 300
    scans_per_hour: int = 30
    max_running_scans_per_user: int = 2
    github_max_mb: int = 50
    github_token: SecretStr | None = None
    ratelimit_storage_uri: str = "memory://"
    ratelimit_enabled: bool = True
    retention_days: int = 90

    # --- Base de datos -------------------------------------------------------------
    db_pool_size: int = 3
    db_max_overflow: int = 2

    log_level: str = "INFO"

    @field_validator("secret_key", "session_hmac_key")
    @classmethod
    def _long_enough(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value().encode("utf-8")) < MIN_SECRET_BYTES:
            raise ValueError(f"debe tener al menos {MIN_SECRET_BYTES} bytes")
        return v

    @field_validator("database_url")
    @classmethod
    def _normalize_db_url(cls, v: str) -> str:
        if v.startswith("postgres://"):
            v = "postgresql://" + v[len("postgres://"):]
        if v.startswith("postgresql://"):
            v = "postgresql+psycopg://" + v[len("postgresql://"):]
        return v

    @model_validator(mode="after")
    def _environment_rules(self) -> "Settings":
        if self.dev_login_enabled and self.environment == "prod":
            raise ValueError("DEV_LOGIN_ENABLED no está permitido con ENVIRONMENT=prod")
        if self.environment == "prod" and not (self.google_client_id and self.google_client_secret):
            raise ValueError("en producción se requieren GOOGLE_CLIENT_ID y GOOGLE_CLIENT_SECRET")
        if self.environment == "prod" and self.database_url.startswith("sqlite"):
            raise ValueError("en producción DATABASE_URL debe ser PostgreSQL")
        return self

    @property
    def allowed_origins(self) -> set[str]:
        return {self.public_origin.rstrip("/"), *(o.rstrip("/") for o in self.extra_allowed_origins)}

    @property
    def provider_name(self) -> str:
        return self.oidc_provider_name or ("Google" if not self.oidc_issuer else "tu cuenta institucional")

    @property
    def is_secure(self) -> bool:
        return self.public_origin.startswith("https://")

    @property
    def admins(self) -> set[str]:
        return {e.strip().lower() for e in self.admin_emails.split(",") if e.strip()}
