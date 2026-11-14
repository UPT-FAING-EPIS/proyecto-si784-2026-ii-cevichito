# SAST Studio: respuesta a la revisión técnica

La revisión planteó cuatro observaciones. Para cada una: qué había, qué hay ahora, cómo
comprobarlo y qué sigue sin resolver. Todo lo citado está en la rama `refactor/fases` del
repositorio.

| Observación | Estado | Prueba principal |
|---|---|---|
| 1. ¿En qué se diferencia? | Respondida con datos; queda validar con estudiantes. | [`docs/benchmark.md`](benchmark.md) |
| 2. Arquitectura frágil | Rehecha y probada con fallos reales. | Worker matado a mitad de escaneo y recuperado |
| 3. Cómo se integran las reglas | Contrato explícito, con pruebas por regla. | `python -m sast test-rules` |
| 4. Base de datos | PostgreSQL con historial entre escaneos. | Comparación de escaneos con el triage conservado |

---

## 1. ¿En qué se diferencia de otros analizadores?

**Qué había.** Un analizador más, con un motor de expresiones regulares, mensajes cortos y el
historial en el navegador.

**Qué hay ahora.** No compite en «quién detecta más», donde las herramientas de pago (Semgrep
Pro, CodeQL, Sonar Developer) son superiores. Ocupa un hueco distinto: **un analizador para
aprender seguridad**, que combina cuatro cosas que ninguna de las herramientas revisadas reúne:

1. **Explicación en español por hallazgo:** qué ocurre, cómo se corrige, un ejemplo vulnerable y
   otro corregido, el CWE y el OWASP, y el recorrido del dato desde la entrada hasta el uso
   peligroso.
2. **Progreso medido entre escaneos:** nuevos, persisten, corregidos y reabiertos. El triage
   (falso positivo, riesgo aceptado) se conserva aunque el código cambie de línea.
3. **Autoalojado con un comando** (`docker compose up`): el código de los estudiantes no sale del
   servidor de la institución.
4. **Reglas pequeñas y legibles**, con casos de prueba: sirven como material de estudio y un
   estudiante puede escribir una nueva.

**Cómo comprobarlo.** El benchmark ([`docs/benchmark.md`](benchmark.md)) compara SAST Studio con
Bandit 1.9.4 y Semgrep CE 1.100.0 sobre los mismos archivos:

| OWASP Benchmark for Python (1230 casos) | SAST Studio | Bandit | Semgrep CE (reglas públicas) |
|---|---:|---:|---:|
| Media de Youden, 14 categorías | **+20** | +17 | +4 |
| Media de Youden, 8 categorías con reglas propias | **+35** | +31 | +8 |
| Inyección SQL | **+100** | +0 | +0 |

Youden = tasa de verdaderos positivos − tasa de falsos positivos. 0 equivale a no distinguir
lo vulnerable de lo seguro; 100 es perfecto.

**Qué sigue abierto.**

- El benchmark muestra tres debilidades con causa conocida: inyección de comandos (−46), XSS
  (−7) y path traversal (+4). Están en `docs/benchmark.md`, con el arreglo propuesto para cada una.
- El análisis es entre funciones, pero **dentro de cada archivo**; no sigue datos entre archivos.
  En JavaScript, PHP y Java solo hay reglas heurísticas.
- Que la explicación en español ayude a aprender es una hipótesis razonable, pero **no está
  medida**. La siguiente prueba debería ser con un curso: dos grupos corrigen el mismo código,
  uno con Bandit y otro con SAST Studio.

---

## 2. «La arquitectura era frágil»

**Qué había.**

- Vercel serverless (4,5 MB por petición y 300 s como máximo).
- Token JWT en `localStorage`, devuelto en la URL del callback de OAuth.
- CORS abierto a cualquier origen y secretos con valor por defecto en el código.
- Dos usuarios demo con contraseña en el código.
- ZIP sin límites de tamaño ni de número de archivos.
- Un motor global recreado en cada petición (condición de carrera) y rutas registradas dos veces.

**Qué hay ahora.**

```text
Navegador ──HTTPS──▶ Gunicorn + Flask (MVC) ──▶ PostgreSQL ◀── Worker ──▶ proceso hijo (motor)
   (misma origen: la web compilada la sirve el mismo servidor)      cola con SKIP LOCKED
```

- **API y worker separados.** La API solo encola. El worker reclama trabajos de una cola en
  PostgreSQL (`SELECT … FOR UPDATE SKIP LOCKED`), manda un latido y analiza en un proceso hijo
  con tiempo límite. Un **reaper** devuelve a la cola los trabajos de un worker caído.
- **Seguridad con objetivo OWASP ASVS 5.0 nivel 2:**
  - login OIDC con PKCE, `state` y `nonce`, que falla cerrado; sirve con Google o con cualquier
    proveedor OIDC;
  - sesión en el servidor con cookie `__Host-`, `HttpOnly`, `Secure` y `SameSite=Strict`;
  - protección CSRF y cabeceras de seguridad;
  - autorización por objeto: un recurso ajeno devuelve 404;
  - límites de ZIP (tamaño, número de archivos, razón de compresión, zip slip) y de descargas de
    GitHub (tamaño y tiempo total);
  - cuotas de escaneo por usuario y limitador de peticiones;
  - auditoría a la que solo se puede añadir.
- **Configuración 12-factor.** Si falta un secreto o es demasiado corto, la app no arranca.
- **Docker multi-etapa** con usuario sin privilegios y healthcheck. Despliegue documentado en
  Render + Neon ([`docs/despliegue-render.md`](despliegue-render.md)).

**Cómo comprobarlo** (probado el 14 de noviembre de 2026 en Docker con PostgreSQL y
`ENVIRONMENT=prod`):

| Prueba | Resultado |
|---|---|
| `docker kill` del worker a mitad de un escaneo (archivo 164 de 344) | El reaper lo devolvió a la cola a los 2 min; terminó en el segundo intento. |
| Login OIDC completo contra un proveedor de pruebas | Sesión creada; un correo no verificado se rechaza y vuelve a la pantalla de acceso. |
| Repositorio que supera los límites (`django/django`) | Rechazado: más de 10 000 entradas. |
| Contenedor con los límites de Render free (512 MB, 0,1 CPU) | 344 archivos analizados con un pico de 387 MB, sin quedarse sin memoria. |
| Descarga lenta de GitHub | Antes podía bloquear el worker; ahora tiene límite total y latido (corregido tras probarlo). |
| Pruebas automáticas | 208 de backend (también contra PostgreSQL 16) y 88 de la web. |

La CI ([`.github/workflows/ci-quality.yml`](../.github/workflows/ci-quality.yml)) ejecuta en cada
push las pruebas en SQLite y en PostgreSQL, la web (lint, pruebas, build), el autoanálisis con
Bandit como control cruzado y comprueba que la imagen Docker arranca.

**Qué sigue abierto.** Falta el primer despliegue público real, con HTTPS y login de Google.

---

## 3. ¿Cómo se integran las reglas?

**Qué había.** Funciones sueltas sin contrato común y sin pruebas por regla.

**Qué hay ahora.**

- **Contrato.** Cada regla declara metadatos inmutables (`RuleMeta`):
  - `id` estable (`py/sql-injection`), severidad, confianza, CWE, OWASP;
  - motor (taint, árbol sintáctico o heurística);
  - explicación, corrección y ejemplos.

  El motor reparte el árbol sintáctico de cada archivo entre las reglas, y estas devuelven
  hallazgos con un formato común.
- **Dos formas de escribirlas:**
  - **Python**, sobre el árbol sintáctico y el análisis de taint compartido. 13 reglas de Python.
  - **YAML**, para heurísticas en varios lenguajes, con un subconjunto del formato de Semgrep.

  En total hay 22 reglas.
- **Fuentes, sinks y sanitizadores** del taint en un único archivo de modelos
  (`sast/taint/models.yaml`), al estilo de Pysa.
- **Compatibilidad hacia atrás.** Si una regla se renombra, `previous_ids` conserva el historial
  de sus hallazgos, y `supersedes` evita avisos duplicados entre reglas.
- **Pruebas por regla** con la convención de Semgrep: `# ruleid:` encima de la línea que debe
  detectarse y `# ok:` encima de la que no; `todoruleid` y `todook` para los fallos conocidos.
  Cada caso real que se escapa se añade como regresión. Ejemplo: la inyección SQL de DVPWA,
  encontrada al escanear el repositorio real.

**Cómo comprobarlo.**

```bash
python -m sast rules                          # catálogo
python -m sast test-rules tests/rules/cases   # todos los casos anotados
```

**Qué sigue abierto.** Falta una guía corta de «cómo escribir una regla nueva», y los tres
arreglos del motor que señala el benchmark.

---

## 4. La base de datos

**Qué había.** No había historial en el servidor: los resultados vivían en `localStorage` del
navegador.

**Qué hay ahora.** PostgreSQL con migraciones versionadas (Alembic) y 10 tablas:

| Tabla | Para qué |
|---|---|
| `users`, `sessions` | Identidad (por `sub` del proveedor, no por correo) y sesiones en el servidor (se guarda el hash del token). |
| `projects`, `scans` | Proyectos y escaneos. La tabla `scans` es también la cola de trabajos. |
| `scan_uploads` | El ZIP o el código pegado, que se borra al terminar el escaneo. |
| `issues` | El problema que vive entre escaneos: estado de ciclo de vida y triage. |
| `occurrences` | Dónde apareció un issue en cada escaneo (archivo, línea, unas líneas de contexto con los secretos enmascarados). |
| `issue_events` | Historial: quién cambió qué y cuándo, y comentarios. |
| `rules` | Catálogo de reglas sincronizado con el motor. |
| `audit_log` | Auditoría a la que solo se puede añadir. |

Decisiones de diseño:

- **Huella estable `sastfp/v1`.** Reconoce el mismo problema aunque cambie de línea: excluye el
  número de línea y se basa en la regla y el contenido normalizado. Está inspirada en las de
  GitHub y SonarQube, con versión explícita por si el algoritmo cambia.
- **Ciclo de vida separado del triage.** El sistema decide nuevo, corregido o reabierto; las
  personas deciden falso positivo o riesgo aceptado. Un falso positivo no se reabre al volver a
  escanear, un error que DefectDojo documentó en su PR #12291.
- **Retención.** Las ocurrencias se purgan a los 90 días; los issues y sus eventos se conservan,
  porque hacen falta para medir el tiempo de corrección.
- **Autorización por objeto** en todas las consultas: cada usuario solo ve lo suyo, y un recurso
  ajeno devuelve 404. Está probado ruta por ruta (`tests/api/test_contract.py`).

**Cómo comprobarlo.** Dos escaneos del mismo proyecto y «Comparar con el anterior». En la prueba
del 14 de noviembre: 35 corregidos, 1 nuevo, 3 persistentes, y el falso positivo marcado en el
primer escaneo siguió marcado en el segundo.

**Qué sigue abierto.** Las copias de seguridad son manuales (`pg_dump`). Neon gratis da 1 GB y
6 h de historial, suficiente para una demo pero no para un curso grande durante un año.

---

## Próximos pasos propuestos

1. Desplegar en Render + Neon y hacer la demo desde la URL pública ([`docs/demo.md`](demo.md)).
2. Arreglar las tres debilidades del benchmark (taint de diccionarios, `sh -c` en listas y XSS
   por valor de retorno) y volver a medir.
3. Una prueba pequeña con estudiantes para medir si la explicación en español mejora las
   correcciones.
