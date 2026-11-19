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

Además, [`.github/workflows/pruebas.yml`](.github/workflows/pruebas.yml) ejecuta en cada push
los cuatro tipos de prueba automatizada y deja sus reportes HTML en el artefacto
`reportes-de-pruebas`:

| Tipo | Herramientas | Informe |
|---|---|---|
| Unitarias y de mutación | pytest, pytest-cov, mutmut | [`docs/pruebas/01-unitarias-y-mutacion.md`](docs/pruebas/01-unitarias-y-mutacion.md) |
| Integración y sistema | pytest con PostgreSQL 16, servidor real por HTTP | [`docs/pruebas/02-integracion-y-sistema.md`](docs/pruebas/02-integracion-y-sistema.md) |
| Interfaz de usuario | Playwright con Chromium | [`docs/pruebas/03-interfaz-de-usuario.md`](docs/pruebas/03-interfaz-de-usuario.md) |
| Aceptación | Gherkin en español con pytest-bdd | [`docs/pruebas/04-aceptacion.md`](docs/pruebas/04-aceptacion.md) |

Cómo ejecutarlas en local: [`docs/pruebas/README.md`](docs/pruebas/README.md).

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

## Automatizaciones en GitHub Actions

| Workflow | Qué hace | Reporte |
|---|---|---|
| `ci-quality.yml` | Pruebas del backend (SQLite y PostgreSQL), web y autoanálisis con Bandit | cobertura, SARIF |
| `pruebas.yml` | Unitarias con mutación, integración, sistema, interfaz y aceptación | `reportes-de-pruebas` |
| `analisis-estatico.yml` | SonarCloud, Semgrep y Snyk (en los repositorios del curso) | `reporte-calidad`: Bugs, Vulnerabilities, Security Hotspots y hallazgos superados |
| `infra.yml` | Terraform de Render y Neon: validar, probar, planificar y aplicar | `reporte-infra`: pruebas superadas y costo mensual |
| `release.yml` | Con una etiqueta `vX.Y.Z`: pruebas, imagen en ghcr.io, release y despliegue en Render | release en GitHub |
| `documentacion.yml` | Diccionario de datos y diagramas en este README; documentación técnica en GitHub Pages | GitHub Pages |
| — | Dashboard de uso del producto en la aplicación: página `/uso` (administradores en `ADMIN_EMAILS`) | — |

<!-- DOCS:INICIO -->
## Documentación generada

Esta sección la actualiza el workflow `documentacion.yml` a partir del código. No la edites a mano.

- [Diccionario de datos](docs/arquitectura/diccionario-datos.md) (11 tablas)
- [Diagrama entidad-relación](docs/arquitectura/diagrama-er.md)
- [Diagrama de clases](docs/arquitectura/diagrama-clases.md)
- [Diagrama de componentes](docs/arquitectura/diagrama-componentes.md)
- [Diagrama de despliegue](docs/arquitectura/diagrama-despliegue.md)

<details><summary>Diagrama entidad-relación</summary>

```mermaid
erDiagram
    audit_log {
        bigint id PK
        datetime at
        varchar event
        varchar user_sub
        varchar ip
        varchar user_agent
        varchar request_id
        varchar target_type
        varchar target_id
        varchar outcome
        json details
    }
    issue_events {
        bigint id PK
        char issue_id FK
        char user_id FK
        varchar kind
        varchar from_state
        varchar to_state
        text comment
        char scan_id FK
        datetime created_at
    }
    issues {
        char id PK
        char project_id FK
        varchar rule_id FK
        varchar category
        varchar fingerprint
        smallint fingerprint_version
        varchar line_hash
        varchar snippet_hash
        varchar lifecycle
        varchar triage
        text triage_justification
        smallint severity
        varchar current_path
        integer current_line
        text message
        char first_seen_scan_id FK
        char last_seen_scan_id FK
        datetime first_seen_at
        datetime fixed_at
        integer reopened_count
        char assignee_id FK
    }
    occurrences {
        char id PK
        char scan_id FK
        char issue_id FK
        varchar path
        integer start_line
        integer end_line
        integer start_col
        integer end_col
        text message
        smallint severity
        smallint confidence
        text snippet
        varchar line_hash
        json trace
        varchar variant
        boolean suppressed
        varchar suppression_reason
        varchar change
    }
    projects {
        char id PK
        char owner_id FK
        varchar name
        datetime created_at
        varchar challenge_id
        datetime challenge_solved_at
    }
    rules {
        varchar id PK
        varchar tool
        varchar name
        smallint default_severity
        smallint confidence
        json cwe
        json owasp
        varchar kind
        varchar engine
        json previous_ids
        json meta
        varchar version
    }
    scan_result_cache {
        varchar key PK
        blob payload
        datetime created_at
        integer hits
    }
    scan_uploads {
        char scan_id PK
        blob content
        varchar filename
        varchar sha256
        integer size
        datetime created_at
    }
    scans {
        char id PK
        char project_id FK
        char created_by FK
        varchar source
        varchar source_ref
        varchar category
        varchar commit_sha
        varchar status
        integer progress_done
        integer progress_total
        integer attempts
        boolean cancel_requested
        datetime heartbeat_at
        varchar worker_id
        datetime queued_at
        datetime started_at
        datetime finished_at
        varchar error_code
        json rules_enabled
        json rules_requested
        varchar engine_version
        integer loc_total
        integer files_scanned
        json summary
        json rule_errors
        char baseline_scan_id FK
        varchar request_id
        boolean partial
        boolean result_reused
    }
    sessions {
        char id PK
        char user_id FK
        varchar token_hash
        varchar csrf_secret
        datetime created_at
        datetime last_seen_at
        datetime expires_at
        datetime revoked_at
        varchar ip
        varchar user_agent
    }
    users {
        char id PK
        varchar google_sub
        varchar email
        varchar name
        datetime created_at
        datetime disabled_at
    }
    issues ||--o{ issue_events : "issue_id"
    issues ||--o{ occurrences : "issue_id"
    projects ||--o{ issues : "project_id"
    projects ||--o{ scans : "project_id"
    rules ||--o{ issues : "rule_id"
    scans |o--o{ issue_events : "scan_id"
    scans |o--o{ issues : "first_seen_scan_id"
    scans |o--o{ issues : "last_seen_scan_id"
    scans |o--o{ scans : "baseline_scan_id"
    scans ||--o{ occurrences : "scan_id"
    scans ||--o{ scan_uploads : "scan_id"
    users |o--o{ issue_events : "user_id"
    users |o--o{ issues : "assignee_id"
    users |o--o{ scans : "created_by"
    users ||--o{ projects : "owner_id"
    users ||--o{ sessions : "user_id"
```

</details>

<details><summary>Diagrama de clases</summary>

```mermaid
classDiagram
    direction LR
    class AuditLog {
        +bigint id
        +datetime at
        +varchar event
        +varchar user_sub
        +varchar ip
        +varchar user_agent
        +varchar request_id
        +varchar target_type
        +varchar target_id
        +varchar outcome
        +json details
    }
    class AuthSession {
        +char id
        +char user_id
        +varchar token_hash
        +varchar csrf_secret
        +datetime created_at
        +datetime last_seen_at
        +datetime expires_at
        +datetime revoked_at
        +varchar ip
        +varchar user_agent
    }
    class Issue {
        +char id
        +char project_id
        +varchar rule_id
        +varchar category
        +varchar fingerprint
        +smallint fingerprint_version
        +varchar line_hash
        +varchar snippet_hash
        +varchar lifecycle
        +varchar triage
        +text triage_justification
        +smallint severity
    }
    class IssueEvent {
        +bigint id
        +char issue_id
        +char user_id
        +varchar kind
        +varchar from_state
        +varchar to_state
        +text comment
        +char scan_id
        +datetime created_at
    }
    class Occurrence {
        +char id
        +char scan_id
        +char issue_id
        +varchar path
        +integer start_line
        +integer end_line
        +integer start_col
        +integer end_col
        +text message
        +smallint severity
        +smallint confidence
        +text snippet
    }
    class Project {
        +char id
        +char owner_id
        +varchar name
        +datetime created_at
        +varchar challenge_id
        +datetime challenge_solved_at
    }
    class RuleRecord {
        +varchar id
        +varchar tool
        +varchar name
        +smallint default_severity
        +smallint confidence
        +json cwe
        +json owasp
        +varchar kind
        +varchar engine
        +json previous_ids
        +json meta
        +varchar version
    }
    class Scan {
        +char id
        +char project_id
        +char created_by
        +varchar source
        +varchar source_ref
        +varchar category
        +varchar commit_sha
        +varchar status
        +integer progress_done
        +integer progress_total
        +integer attempts
        +boolean cancel_requested
    }
    class ScanResultCache {
        +varchar key
        +blob payload
        +datetime created_at
        +integer hits
    }
    class ScanUpload {
        +char scan_id
        +blob content
        +varchar filename
        +varchar sha256
        +integer size
        +datetime created_at
    }
    class User {
        +char id
        +varchar google_sub
        +varchar email
        +varchar name
        +datetime created_at
        +datetime disabled_at
    }
    class RuleMeta {
        +str id
        +str name
        +str message
        +Severity severity
        +Confidence confidence
        +tuple languages
        +tuple cwe
        +tuple owasp
        +str kind
        +str engine
        +float security_severity
        +tuple previous_ids
        +to_dict()
    }
    class Finding {
        +str rule_id
        +str path
        +int line
        +int col
        +int end_line
        +int end_col
        +str message
        +Severity severity
        +Confidence confidence
        +tuple trace
        +str variant
        +bool suppressed
        +sort_key()
        +to_dict()
        +with_()
    }
    class TraceStep {
        +int line
        +str description
        +to_dict()
    }
    class RuleError {
        +str rule_id
        +str path
        +str exc_type
        +str message
        +to_dict()
    }
    class PythonRule {
        +check()
        +finding()
    }
    class Engine {
        +analyze()
        +collect()
        +scan_files()
        +scan_path()
        +scan_source()
    }
    class EngineConfig {
        +Confidence min_confidence
        +Severity min_severity
        +bool exclude_tests
        +tuple exclude_globs
        +tuple excluded_dirs
        +int max_file_bytes
        +bool include_suppressed
    }
    class ScanReport {
        +str target
        +list findings
        +list rule_errors
        +list file_errors
        +int files_scanned
        +int loc_total
        +list rules_enabled
        +str engine_version
        +str started_at
        +str finished_at
        +int duration_ms
        +dict sources
        +prune_sources()
        +to_dict()
    }
    class FileContext {
        +is_comment_line()
        +line()
        +qualname()
        +snippet()
        +suppression_for()
    }
    User "1" <-- "*" AuthSession
    Project "1" <-- "*" Issue
    RuleRecord "1" <-- "*" Issue
    Scan "1" <-- "*" Issue
    User "1" <-- "*" Issue
    Issue "1" <-- "*" IssueEvent
    User "1" <-- "*" IssueEvent
    Scan "1" <-- "*" IssueEvent
    Scan "1" <-- "*" Occurrence
    Issue "1" <-- "*" Occurrence
    User "1" <-- "*" Project
    Project "1" <-- "*" Scan
    User "1" <-- "*" Scan
    Scan "1" <-- "*" Scan
    Scan "1" <-- "*" ScanUpload
    Engine ..> FileContext : analiza
    Engine ..> ScanReport : produce
    ScanReport o-- Finding
    Finding o-- TraceStep
    PythonRule ..> RuleMeta
    Occurrence ..> Finding : se guarda como
```

</details>

<details><summary>Diagrama de componentes</summary>

```mermaid
flowchart LR
    usuario([Navegador])
    subgraph web["SPA (React + Vite) — web/"]
        paginas[Páginas] --> cliente[api/client.ts]
    end
    subgraph api["API Flask — api/"]
        seguridad[security: sesión, CSRF, cabeceras]
        c_auth["auth · /api/v1/auth"]
        c_challenges["challenges · /api/v1/challenges"]
        c_config["config · /api/v1/config"]
        c_issues["issues · /api/v1/issues"]
        c_projects["projects · /api/v1/projects"]
        c_rules["rules · /api/v1/rules"]
        c_scans["scans · /api/v1/scans"]
        c_usage["usage · /api/v1/usage"]
        servicios[services]
        modelos[models: SQLAlchemy]
    end 
    worker[[Worker — api/worker]]
    motor[[Motor SAST — sast/]]
    db[(PostgreSQL)]
    kv[(Valkey: límite de peticiones)]
    google{{Google OIDC}}
    github{{GitHub: descarga de repos}}
    usuario --> paginas
    cliente -->|"/api/v1, cookie + X-CSRF-Token"| seguridad
    seguridad --> c_auth --> servicios
    seguridad --> c_challenges --> servicios
    seguridad --> c_config --> servicios
    seguridad --> c_issues --> servicios
    seguridad --> c_projects --> servicios
    seguridad --> c_rules --> servicios
    seguridad --> c_scans --> servicios
    seguridad --> c_usage --> servicios
    servicios --> modelos --> db
    servicios --> kv
    servicios --> google
    worker -->|"cola: SELECT … SKIP LOCKED"| db
    worker --> motor
    worker --> github
```

</details>

<details><summary>Diagrama de despliegue</summary>

```mermaid
flowchart TB
    subgraph local["Local: docker compose"]
        l_db["db<br/>postgres:16-alpine"]
        l_valkey["valkey<br/>valkey/valkey:8-alpine"]
        l_migrate["migrate<br/>sast-studio:local"]
        l_api["api<br/>sast-studio:local · 8080:8000"]
        l_worker["worker<br/>sast-studio:local"]
    end
    subgraph nube["Producción: Render + Neon"]
        r_sast_studio["sast-studio<br/>web · plan free"]
        r_sast_ratelimit["sast-ratelimit<br/>keyvalue · plan free"]
        neon[(Neon PostgreSQL · plan free)]
    end
    l_api --> l_db
    l_worker --> l_db
    l_api --> l_valkey
    l_migrate --> l_db
    r_sast_studio --> neon
    r_sast_studio --> r_sast_ratelimit
    gh[GitHub Actions] -->|release: imagen + deploy hook| r_sast_studio
```

</details>
<!-- DOCS:FIN -->

## Licencia

MIT, según `pyproject.toml`.
