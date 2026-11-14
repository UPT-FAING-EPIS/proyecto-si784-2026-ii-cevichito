"""Configuración de Gunicorn: la capa HTTP solo hace E/S (el análisis va al worker)."""

import multiprocessing
import os

# Render (y otros PaaS) indican el puerto en $PORT; en compose se usa el 8000.
bind = os.environ.get("GUNICORN_BIND") or f"0.0.0.0:{os.environ.get('PORT', '8000')}"
worker_class = "gthread"
workers = int(os.environ.get("WEB_CONCURRENCY", min(4, multiprocessing.cpu_count() * 2)))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))
timeout = 30                 # no se sube para ocultar escaneos lentos
graceful_timeout = 20
keepalive = 5
max_requests = 1000
max_requests_jitter = 100
worker_tmp_dir = "/dev/shm"
accesslog = None             # la app emite su propio log JSON por petición
errorlog = "-"
forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1")
# Gunicorn 27 abre un socket de control en $HOME/.gunicorn; no se usa, y el usuario sin
# privilegios del contenedor no puede escribir en /app (daba "Permission denied" en el log).
control_socket_disable = True
