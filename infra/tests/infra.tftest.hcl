# Pruebas de la infraestructura sin tocar la nube: los proveedores son simulados.
# Ejecutar con:  terraform test   (dentro de infra/)

mock_provider "render" {
  mock_resource "render_keyvalue" {
    defaults = {
      id = "red-mock"
      connection_info = {
        internal_connection_string = "redis://red-mock:6379"
        external_connection_string = "rediss://red-mock.render.com:6379"
        cli_command                = "redis-cli"
      }
    }
  }
  mock_resource "render_web_service" {
    defaults = {
      id  = "srv-mock"
      url = "https://sast-studio-iac.onrender.com"
    }
  }
}

mock_provider "neon" {}

variables {
  database_url = "postgresql://u:p@ep-mock.us-east-1.aws.neon.tech/sast?sslmode=require"
}

run "planes_gratis_por_defecto" {
  command = plan

  assert {
    condition     = render_web_service.app.plan == "free" && length(render_keyvalue.ratelimit) == 0
    error_message = "Por defecto el web va en plan gratis y no se crea un segundo Key Value (Render permite uno gratis)."
  }
  assert {
    condition     = render_web_service.app.env_vars["RATELIMIT_STORAGE_URI"].value == "memory://"
    error_message = "Sin Key Value propio, el límite de peticiones va en memoria."
  }
}

run "key_value_opcional" {
  command = apply # con proveedores simulados: no crea nada real

  variables {
    crear_keyvalue = true
  }

  assert {
    condition     = length(render_keyvalue.ratelimit) == 1 && render_keyvalue.ratelimit[0].plan == "free"
    error_message = "Con crear_keyvalue se crea un Key Value en plan gratis."
  }
  assert {
    condition     = render_web_service.app.env_vars["RATELIMIT_STORAGE_URI"].value == "redis://red-mock:6379"
    error_message = "El servicio usa la conexión interna del Key Value."
  }
}

run "misma_region_que_la_base_de_datos" {
  command = plan

  assert {
    condition     = render_web_service.app.region == "virginia" && neon_project.db.region_id == "aws-us-east-1"
    error_message = "Render y Neon deben estar en el este de EE. UU. para no sumar latencia."
  }
}

run "servicio_docker_con_healthcheck" {
  command = plan

  assert {
    condition     = render_web_service.app.health_check_path == "/healthz"
    error_message = "Render debe vigilar /healthz."
  }
  assert {
    condition     = render_web_service.app.runtime_source.docker.dockerfile_path == "./Dockerfile"
    error_message = "El servicio se construye con el Dockerfile del repositorio."
  }
  assert {
    condition     = render_web_service.app.runtime_source.docker.auto_deploy == false
    error_message = "El despliegue lo hace el workflow de release, no cada commit."
  }
}

run "configuracion_segura" {
  command = plan

  assert {
    condition     = render_web_service.app.env_vars["DEV_LOGIN_ENABLED"].value == "false"
    error_message = "El acceso de desarrollo no puede estar activo en producción."
  }
  assert {
    condition     = render_web_service.app.env_vars["ENVIRONMENT"].value == "prod"
    error_message = "El entorno debe ser prod."
  }
  assert {
    condition     = render_web_service.app.env_vars["SECRET_KEY"].generate_value && render_web_service.app.env_vars["SESSION_HMAC_KEY"].generate_value
    error_message = "Los secretos los genera Render; no se escriben en el código."
  }
}

run "base_de_datos_postgres_16" {
  command = plan

  assert {
    condition     = neon_project.db.pg_version == 16 && neon_project.db.database_name == "sast"
    error_message = "La base de datos debe ser PostgreSQL 16 con la base sast."
  }
}

run "plan_pago_se_puede_elegir" {
  command = plan

  variables {
    plan_web = "starter"
  }

  assert {
    condition     = render_web_service.app.plan == "starter"
    error_message = "El plan del servicio web debe poder cambiarse por variable."
  }
}
