# Infraestructura de SAST Studio: lo mismo que render.yaml, pero con Terraform.
#   - Neon: proyecto PostgreSQL (plan gratis).
#   - Render: Key Value para el límite de peticiones y el servicio web (API + worker en el
#     mismo contenedor, porque el plan gratis no tiene workers de fondo).

resource "neon_project" "db" {
  name          = var.nombre
  org_id        = var.neon_org_id
  region_id     = var.region_neon
  pg_version    = 16
  database_name = "sast"
  database_user = "sast"

  branch = {
    name = "main"
  }
}

resource "render_keyvalue" "ratelimit" {
  count             = var.crear_keyvalue ? 1 : 0
  name              = "${var.nombre}-ratelimit"
  plan              = var.plan_keyvalue
  region            = var.region_render
  max_memory_policy = "allkeys_lru"
}

locals {
  # Mismos valores que render.yaml (docs/despliegue-render.md explica cada límite).
  env = {
    ENVIRONMENT               = { value = "prod" }
    RUN_MIGRATIONS            = { value = "1" }
    SECRET_KEY                = { generate_value = true }
    SESSION_HMAC_KEY          = { generate_value = true }
    DATABASE_URL              = { value = var.database_url }
    GOOGLE_CLIENT_ID          = { value = var.google_client_id }
    GOOGLE_CLIENT_SECRET      = { value = var.google_client_secret }
    ADMIN_EMAILS              = { value = var.admin_emails }
    TRUST_PROXY               = { value = "true" }
    FORWARDED_ALLOW_IPS       = { value = "*" }
    RATELIMIT_STORAGE_URI     = { value = var.crear_keyvalue ? render_keyvalue.ratelimit[0].connection_info.internal_connection_string : "memory://" }
    WEB_CONCURRENCY           = { value = "1" }
    GUNICORN_THREADS          = { value = "4" }
    DB_POOL_SIZE              = { value = "2" }
    DB_MAX_OVERFLOW           = { value = "1" }
    MAX_UPLOAD_MB             = { value = "25" }
    GITHUB_MAX_MB             = { value = "40" }
    MAX_TOTAL_UNCOMPRESSED_MB = { value = "150" }
    MAX_ZIP_ENTRIES           = { value = "5000" }
    DEV_LOGIN_ENABLED         = { value = "false" }
    LOG_LEVEL                 = { value = "INFO" }
  }
}

resource "render_web_service" "app" {
  name              = var.nombre
  plan              = var.plan_web
  region            = var.region_render
  health_check_path = "/healthz"
  start_command     = "docker/start-embedded.sh"

  runtime_source = {
    docker = {
      repo_url        = var.repo_url
      branch          = var.rama
      dockerfile_path = "./Dockerfile"
      auto_deploy     = false # se despliega desde el workflow de release
    }
  }

  env_vars = local.env
}
