# Estado de la refactorización (rama `refactor/fases`)

| Fase | Estado | Pruebas |
|---|---|---|
| F0 Línea base, dependencias, corpus anotado | Hecha | `tests/rules`, `tests/golden` |
| F1-F2 Motor de reglas + taint entre funciones | Hecha | `tests/engine`, `tests/test_cli.py` |
| F3 App factory, configuración, PostgreSQL | Hecha | `tests/api/test_persistence.py` |
| F4 Worker, ZIP seguro, GitHub, Docker | Hecha | `tests/api/test_worker.py`; `docker compose up` verificado (`/healthz` y `/readyz` en verde) |
| F5 Seguridad (BFF, OIDC, CSRF, cabeceras, límites) | Hecha | `tests/api/test_security.py` |
| F6 API v1 completa, OpenAPI, BOLA | Hecha | `tests/api/test_contract.py`, `test_openapi.py` (133 pruebas de API pasan en PostgreSQL 16) |
| F7 Interfaz web (shadcn/ui + tokens de Sentry, sin "look IA") | Hecha | `web/src/test` (88 pruebas con Vitest); prueba manual completa en navegador a 1920, 1366 y 375 px |
| F8 Benchmark vs Bandit/Semgrep, CI ampliado, README final | Hecha salvo el despliegue real (lo hace el usuario con `docs/despliegue-render.md`) | `docs/benchmark.md`, `.github/workflows/ci-quality.yml`, `tests/engine/test_bench.py` |

## Verificado de extremo a extremo (2026-11-14, Docker + PostgreSQL, ENVIRONMENT=prod)
- Login OIDC real contra un proveedor de pruebas (`docker/compose.oidc-test.yml`): PKCE, state, nonce,
  cookie HttpOnly, usuario `issuer|sub`, rechazo con email no verificado y vuelta a /login.
- Repositorios reales de GitHub: pallets/flask, anxolerd/dvpwa, OWASP/NodeGoat, psf/requests@v2.31.0,
  sqlalchemy/sqlalchemy; repo y rama inexistentes (`repo_not_found`); django/django rechazado por
  superar 10 000 entradas; tope de 2 escaneos simultáneos por usuario (429).
- Worker matado con `docker kill` a mitad de escaneo (164/344 archivos): el reaper lo devolvió a la
  cola a los 2 min y terminó en el segundo intento.

## Despliegue elegido: Render free + Neon free
`render.yaml` + `docs/despliegue-render.md`. Web y worker en un solo contenedor
(`docker/start-embedded.sh`). Probado en local con los límites de Render (512 MB, 0,1 CPU,
`PORT=10000`): arranca en ~50 s, usa 213 MB en reposo y escanea sqlalchemy (344 archivos) en
120 s con un pico de 387 MB. Si el worker muere, el contenedor sale con código 1; con SIGTERM,
sale limpio. Falta: crear las cuentas (Neon, Google, Render) y el primer despliegue real.

## Cola, caché y límites (2026-11-14)
Cola con prioridad (código pegado y ZIP pequeños primero), turnos por usuario y envejecimiento
a los 5 min; posición y estimación en la web. Caché de resultados por contenido (TTL 7 días):
otro usuario escaneando el mismo commit tardó 9 s en vez de ~2 min. Resultado parcial al
agotar el tiempo. El límite de archivos cuenta solo código; pruebas y minificados se descartan
al descomprimir. Pico de RAM medido como Render: 350–353 MB con sqlalchemy y django, lo que
permitió subir los límites (ZIP 25 MB, GitHub 40 MB, 150 MB descomprimidos).

## Para retomar
1. Login con Google de verdad: falta un GOOGLE_CLIENT_ID/SECRET real (Google Cloud Console).
2. Arreglar las tres debilidades del benchmark (taint de diccionarios, `sh -c` en listas, XSS por valor de retorno) y volver a medir con `sast bench`.
3. Límites conocidos del motor vistos con repos reales: el taint es intra-archivo (en DVPWA la
   inyección SQL solo la ve la variante heurística); en JavaScript solo hay reglas heurísticas
   (NodeGoat: no detecta NoSQL injection ni SSRF; `eval` sale como alta, no crítica) y las páginas
   HTML de tutoriales con ejemplos de código generan ruido.
4. Pendiente medido: el motor va a 34 ms/KLOC (meta 1/3 del heredado = 23 ms/KLOC, no alcanzada).

Entorno local: `docker compose up -d` (usa `.env`, no versionado). Pruebas: `pytest` (SQLite) o
`TEST_DATABASE_URL=postgresql://... pytest tests/api` (PostgreSQL).
