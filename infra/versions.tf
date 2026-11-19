terraform {
  required_version = ">= 1.11"

  # El estado se guarda en PostgreSQL (esquema terraform_remote_state). La conexión llega
  # por la variable de entorno PG_CONN_STR. Para validar y probar: terraform init -backend=false
  backend "pg" {}

  required_providers {
    render = {
      source  = "render-oss/render"
      version = ">= 1.0, < 2.0"
    }
    neon = {
      source  = "neondatabase/neon"
      version = "0.19.0-beta.3" # beta: Terraform solo la instala si se nombra exacta
    }
  }
}

# Las credenciales llegan por variables de entorno, nunca en estos archivos:
#   RENDER_API_KEY y RENDER_OWNER_ID para Render, NEON_API_KEY para Neon.
provider "render" {}

provider "neon" {}
