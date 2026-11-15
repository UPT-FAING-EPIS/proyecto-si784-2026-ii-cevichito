# SAST Studio

## Información

- **Asignatura:** Calidad y Pruebas de Software (SI-784)
- **Docente:** Mg. Ing. Patrick José Cuadros Quiroga
- **Integrantes:**
  - Sagua Ramos, Gustavo Alonso (2018062254)
  - Serrano Ibañez, Nestor Juice Yomar (2022075747)

| Enlace | URL |
|---|---|
| Repositorio | <https://github.com/UPT-FAING-EPIS/proyecto-si784-2026-ii-cevichito> |
| Aplicación publicada | <https://sast-studio.onrender.com> (plan gratis: tarda 1–2 min en despertar) |

Los documentos del curso (FD01 a FD06) están en la raíz del repositorio.

---

Analizador estático de seguridad **didáctico y autoalojado** que **enseña a corregir**. Cada
hallazgo explica qué ocurre, por qué es peligroso y cómo corregirlo, con un ejemplo vulnerable y
otro corregido, y su CWE y OWASP. Los **retos de corrección** ponen en práctica lo aprendido:
el usuario arregla código vulnerable en el navegador y el propio analizador comprueba si lo
corrigió de verdad. Guarda el historial de cada proyecto para ver qué hallazgos son nuevos,
cuáles se corrigieron y cuáles siguen ahí. Se instala con Docker y PostgreSQL, sin enviar el
código a terceros.

Está pensado para **aprender seguridad**: en un curso, en un laboratorio o por tu cuenta. No
pretende sustituir a un escáner de producción como Semgrep Pro o CodeQL.

## Qué hace

- **Analiza código Python** con reglas sobre el árbol sintáctico y un análisis de *taint* que
  sigue los datos del usuario entre funciones de un mismo archivo, hasta una consulta SQL, un
  comando del sistema, una ruta de archivo, etc.
- **Busca patrones en JavaScript/TypeScript, PHP, Java, Kotlin, Go, Ruby, C# y plantillas
  HTML/Vue/Svelte** con reglas heurísticas de menor confianza.
- **Explica cada hallazgo:** el recorrido del dato desde la entrada hasta el uso peligroso, qué
  ocurre, cómo se corrige y un ejemplo vulnerable y otro corregido.
- **Retos de corrección** (`/retos`): 8 ejercicios con código vulnerable preparado (inyección
  SQL, inyección de comandos, path traversal, XSS, hash débil, secreto en el código, `eval` y
  `pickle`). Se corrige en un editor dentro del navegador, con pistas de una en una, y el
  analizador da el veredicto: superado, la vulnerabilidad sigue, se silenció en vez de
  corregirse o apareció un fallo nuevo. Cada usuario ve cuántos retos lleva superados.
- **Mide el progreso entre escaneos:** nuevos, persisten, corregidos y reabiertos. Cada problema
  tiene una huella estable que sobrevive a los cambios de línea, y tu revisión (falso positivo,
  riesgo aceptado) se conserva al volver a escanear.
- **Analiza código pegado, un ZIP o un repositorio público de GitHub.** Omite pruebas,
  dependencias y archivos minificados, igual que la línea de comandos.
- **Exporta** a SARIF 2.1.0 (GitHub Code Scanning, DefectDojo), JSON y HTML.
- **Se usa desde la web o desde la línea de comandos** (`python -m sast`).

## Cuánto detecta

Medido con `sast bench` sobre el corpus neutral
[OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) (1230 casos),
frente a Bandit 1.9.4 y Semgrep CE 1.100.0 con reglas públicas. La métrica es la de OWASP:
**Youden = tasa de verdaderos positivos − tasa de falsos positivos** (0 = no distingue lo
vulnerable de lo seguro; 100 = perfecto).

| | SAST Studio | Bandit | Semgrep CE |
|---|---:|---:|---:|
| Media, 14 categorías | **+20** | +17 | +4 |
| Media, las 8 categorías con reglas propias | **+35** | +31 | +8 |
| Inyección SQL | **+100** | +0 | +0 |

Puntos débiles medidos: inyección de comandos (−46), XSS (−7) y path traversal (+4). Las causas
y el método completo están en [`docs/benchmark.md`](docs/benchmark.md).

**Límites conocidos**

- El análisis de *taint* es entre funciones, pero **dentro de cada archivo**: no sigue un dato
  que entra por un archivo y llega a la consulta en otro.
- Fuera de Python solo hay reglas heurísticas.
- Semgrep Pro y CodeQL no se evaluaron.

## Puesta en marcha

### Con Docker (recomendado)

Requisitos: Docker con Compose v2.

```bash
cp .env.example .env
```

Edita `.env`:

- `SECRET_KEY` y `SESSION_HMAC_KEY`: genera cada uno con
  `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
- `POSTGRES_PASSWORD` y la misma contraseña dentro de `DATABASE_URL`.
- Para probar sin configurar Google: `ENVIRONMENT=dev` y `DEV_LOGIN_ENABLED=true`. Así entras
  con cualquier correo y sin contraseña. **Nunca en un servidor público.**

```bash
docker compose up -d --build
```

Abre <http://localhost:8080>. `docker compose up` levanta PostgreSQL, Valkey (limitador de
peticiones), las migraciones, la API con la web y el worker de escaneos.

### Solo la línea de comandos

Requisitos: Python 3.11 o superior.

```bash
pip install -e .
python -m sast scan ruta/al/proyecto                 # resultado en la consola
python -m sast scan ruta -f sarif -o informe.sarif   # SARIF, JSON o HTML
python -m sast scan ruta --severity-threshold high   # sale con código 1 si hay altos o críticos
python -m sast rules                                 # catálogo de reglas
```

### Desarrollo de la web

Con la pila de Docker en marcha:

```bash
cd web
npm ci
npm run dev   # http://localhost:5173; /api se reenvía a localhost:8080
```

## Arquitectura

```text
Navegador ──▶ Gunicorn + Flask (MVC) ──▶ PostgreSQL ◀── Worker ──▶ proceso hijo (motor sast/)
              también sirve la web       cola de escaneos con SKIP LOCKED
```

- **`sast/`**: el motor. Reglas con contrato (`RuleMeta`), análisis de *taint* con modelos de
  fuentes y sinks en `sast/taint/models.yaml`, huella estable `sastfp/v1` e informes.
- **`api/`**: Flask con modelos SQLAlchemy, servicios, controladores finos y serializadores.
  Incluye la autenticación OIDC (Google por defecto u otro proveedor con `OIDC_ISSUER`), la
  sesión en el servidor con cookie `__Host-`, CSRF y la autorización por objeto.
- **`api/worker/`**: reclama escaneos de la cola, analiza en un proceso hijo con tiempo límite y
  manda un latido. Un *reaper* devuelve a la cola los trabajos de un worker caído.
  - **Orden de la cola:** primero el código pegado y los ZIP pequeños; entre iguales, turno
    para el usuario al que hace más tiempo que no se atiende; un escaneo que lleva más de
    5 minutos esperando sube de prioridad. La web muestra cuántos hay delante y una estimación.
  - **Caché por contenido:** si llega exactamente el mismo código (mismas reglas y versión del
    motor), se reutiliza el resultado en vez de volver a analizarlo. Cada escaneo conserva su
    propio historial. Útil cuando un curso entero escanea el mismo repositorio.
  - **Resultado parcial:** si se agota el tiempo, se guarda lo analizado y se indica cuántos
    archivos faltaron, en vez de perderlo todo.
- **`api/challenges/`**: el catálogo de retos. Cada reto es una carpeta en `data/` con su
  enunciado y pistas (`reto.yaml`), el código vulnerable y una solución de referencia que las
  pruebas verifican. Un intento se guarda como un proyecto oculto del usuario; el veredicto
  compara el escaneo del código de partida con el del envío.
- **`web/`**: React + TypeScript con componentes shadcn/ui y los tokens de [`web/DESIGN.md`](web/DESIGN.md).

La seguridad sigue OWASP ASVS 5.0 nivel 2 como objetivo. Algunos ejemplos:

- secretos solo desde el entorno, y la app no arranca si falta uno;
- login OIDC con PKCE, `state` y `nonce`;
- límites de ZIP contra bombas y *zip slip*;
- cuotas por usuario;
- auditoría a la que solo se puede añadir.

## Reglas

22 reglas: 13 de Python, 8 heurísticas para otros lenguajes y 1 de secretos que se aplica a
cualquier archivo. Cada una tiene su página en
[`docs/rules/`](docs/rules/README.md) y casos de prueba anotados en `tests/rules/cases/`, con la
convención de Semgrep:

```python
# ruleid: py/sql-injection
cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)

# ok: py/sql-injection
cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
```

```bash
python -m sast test-rules tests/rules/cases
```

Una regla se escribe como clase de Python (sobre el árbol sintáctico o el *taint*) o en YAML
(heurísticas, con un subconjunto del formato de Semgrep), siempre con su archivo de casos.

## Pruebas

```bash
pip install -e ".[dev]"
python -m pytest                                                 # SQLite en memoria
TEST_DATABASE_URL=postgresql://usuario:clave@localhost:5432/sast_test python -m pytest tests/api
cd web && npm test
```

La CI ([`.github/workflows/ci-quality.yml`](.github/workflows/ci-quality.yml)) ejecuta en cada
push:

- las pruebas en SQLite y en PostgreSQL 16;
- la web: lint, pruebas y build;
- el autoanálisis con SAST Studio y Bandit;
- un arranque de la imagen Docker igual al de Render.

## Despliegue

- **Publicado:** <https://sast-studio.onrender.com>, en Render con la base de datos en Neon.
- **Local o en un servidor propio:** `docker compose up`, ver «Puesta en marcha».
- **Gratis en Render + Neon:** [`render.yaml`](render.yaml) y la guía paso a paso
  [`docs/despliegue-render.md`](docs/despliegue-render.md). En el plan gratis, web y worker
  comparten contenedor, y el servicio se duerme tras 15 minutos sin uso.

## Documentación

| Documento | Contenido |
|---|---|
| [`docs/benchmark.md`](docs/benchmark.md) | Método y resultados frente a Bandit y Semgrep. |
| [`docs/despliegue-render.md`](docs/despliegue-render.md) | Despliegue en Render + Neon con login de Google. |
| [`docs/demo.md`](docs/demo.md) | Guion de demo de 5 minutos. |
| [`docs/respuesta-revision.md`](docs/respuesta-revision.md) | Respuesta a la revisión técnica: diferenciación, arquitectura, reglas y base de datos. |
| [`docs/api/openapi.yaml`](docs/api/openapi.yaml) | Contrato de la API `/api/v1`. |
| [`docs/rules/`](docs/rules/README.md) | Una página por regla. |

## Licencia

MIT, según `pyproject.toml`.
