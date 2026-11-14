#!/bin/sh
# Web y worker en el MISMO contenedor, para PaaS sin workers de fondo gratis (Render free).
#
#   CMD ["docker/start-embedded.sh"]
#
# Migra la base de datos antes de arrancar (salvo RUN_MIGRATIONS=0). No se puede confiar en
# el ENTRYPOINT: Render ejecuta `dockerCommand` sin él, y el worker fallaba con
# `relation "rules" does not exist`. Si el entrypoint ya migró, marca MIGRATIONS_DONE=1.
#
# Si cualquiera de los dos procesos muere solo, se para el otro y el contenedor sale con
# error para que la plataforma lo reinicie. Un escaneo cortado a medias lo recupera el reaper.
set -u

if [ "${RUN_MIGRATIONS:-1}" != "0" ] && [ "${MIGRATIONS_DONE:-0}" != "1" ]; then
  echo "start-embedded: aplicando migraciones" >&2
  if ! flask db upgrade; then
    echo "start-embedded: las migraciones fallaron; no arranco" >&2
    exit 1
  fi
fi

python -m api.worker &
WORKER=$!
gunicorn -c gunicorn.conf.py api.wsgi:app &
WEB=$!

SIGNALED=0
stop() {
  kill -TERM "$WEB" "$WORKER" 2>/dev/null || true
}
trap 'SIGNALED=1; stop' TERM INT

while [ "$SIGNALED" = "0" ] && kill -0 "$WEB" 2>/dev/null && kill -0 "$WORKER" 2>/dev/null; do
  sleep 1
done

stop
wait "$WEB" 2>/dev/null
wait "$WORKER" 2>/dev/null
if [ "$SIGNALED" = "1" ]; then
  exit 0
fi
echo "start-embedded: un proceso terminó inesperadamente; salgo para que se reinicie el contenedor" >&2
exit 1
