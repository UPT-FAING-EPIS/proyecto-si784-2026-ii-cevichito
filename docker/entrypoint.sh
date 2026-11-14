#!/bin/sh
# Punto de entrada del contenedor.
# RUN_MIGRATIONS=1 aplica las migraciones antes de arrancar (útil en un PaaS con
# una sola instancia). En docker compose se usa el servicio "migrate".
set -eu
if [ "${RUN_MIGRATIONS:-0}" = "1" ]; then
  flask db upgrade
  # start-embedded.sh también sabe migrar (Render se salta este entrypoint); así no lo repite.
  export MIGRATIONS_DONE=1
fi
exec "$@"
