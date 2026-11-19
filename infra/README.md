# Infraestructura con Terraform

Crea lo mismo que `render.yaml`, pero como código de Terraform:

| Recurso | Proveedor | Plan por defecto |
|---|---|---|
| `neon_project.db` (PostgreSQL 16) | `neondatabase/neon` | free |
| `render_keyvalue.ratelimit` (límite de peticiones) | `render-oss/render` | free |
| `render_web_service.app` (API + worker, imagen Docker) | `render-oss/render` | free |

El workflow [`infra.yml`](../.github/workflows/infra.yml) valida, prueba y planifica en cada
cambio, y publica un reporte con las pruebas superadas y el costo mensual estimado
(artefacto `reporte-infra`). Aplicar es manual: *Actions → Infraestructura (Terraform) →
Run workflow → aplicar*.

## Probar en local

```bash
cd infra
terraform init -backend=false
terraform validate
terraform test
```

Las pruebas (`tests/infra.tftest.hcl`) usan proveedores simulados: no crean nada ni piden
credenciales.

## Aplicar

Hacen falta los secretos `RENDER_API_KEY`, `RENDER_OWNER_ID`, `NEON_API_KEY`, `TF_STATE_PG`
(PostgreSQL donde se guarda el estado) y `DATABASE_URL`. Neon no entrega la contraseña por
Terraform, así que la cadena de conexión de la aplicación se copia de la consola de Neon al
secreto `DATABASE_URL` después del primer `apply`.

Los recursos se llaman `sast-studio-iac` para no pisar el servicio que ya existe en Render.
