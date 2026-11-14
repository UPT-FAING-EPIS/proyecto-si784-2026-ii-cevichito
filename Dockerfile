# syntax=docker/dockerfile:1.7
# Imagen única para api, worker y migraciones (cambia solo el comando).

# --- 1. SPA (React + Vite) ------------------------------------------------------
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# --- 2. Dependencias de Python (wheels) -------------------------------------------
FROM python:3.12-slim AS deps
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.lock ./
RUN pip wheel --wheel-dir /wheels -r requirements.lock

# --- 3. Imagen final ---------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 \
    FLASK_APP=api.wsgi:app SPA_DIR=/app/web/dist
RUN groupadd --system app && useradd --system --gid app --home-dir /app --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=deps /wheels /wheels
RUN pip install --no-index --find-links=/wheels /wheels/* && rm -rf /wheels
COPY pyproject.toml README.md ./
COPY sast/ sast/
COPY api/ api/
COPY migrations/ migrations/
COPY docker/ docker/
COPY gunicorn.conf.py ./
# sed: por si el repo se clonó en Windows con finales CRLF (romperían el shebang).
RUN pip install --no-deps . && sed -i 's/\r$//' docker/*.sh && chmod +x docker/entrypoint.sh docker/start-embedded.sh
COPY --from=web /web/dist /app/web/dist
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT', '8000'), timeout=4).status == 200 else 1)"
ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["gunicorn", "-c", "gunicorn.conf.py", "api.wsgi:app"]
