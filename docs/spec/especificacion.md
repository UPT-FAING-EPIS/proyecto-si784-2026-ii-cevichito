# Refactorizar SAST Studio como herramienta didáctica verificable

**Resumen.** SAST Studio no puede ganar en capacidad de detección. Lo que importa para la precisión (taint inter-procedural y entre archivos) está en productos de pago o en plataformas maduras como Sonar Developer+, Semgrep Pro y CodeQL ([Sonar Developer](https://www.sonarsource.com/products/sonarqube/developer-edition/); [Semgrep Pricing](https://semgrep.dev/pricing)). Su valor defendible está en otro sitio: una herramienta **self-hosted, gratuita y didáctica**, con explicaciones y correcciones en español para cada hallazgo, historial de progreso entre escaneos y reglas que se pueden leer y ampliar como material de estudio. La refactorización tiene que responder a las cuatro observaciones del ingeniero con piezas concretas:

- **Valor:** una propuesta de valor sin afirmaciones exageradas, respaldada por un mini-benchmark reproducible.
- **Reglas:** un motor con contrato explícito (`Rule`, `RuleMeta`, `FileContext`, registro, reglas YAML, tests anotados) en lugar de una lista fija de 12 clases.
- **Infraestructura:** salir de Vercel serverless (4,5 MB por petición, 300 s máximo en Hobby) a un contenedor con un worker asíncrono ([Vercel Limits](https://vercel.com/docs/functions/limitations)), con autenticación BFF y cookies `__Host-` que cumplan OWASP ASVS 5.0 nivel 2.
- **Base de datos:** PostgreSQL con un modelo de *issue persistente + ocurrencia por escaneo* y un fingerprint que sobrevive a cambios de línea, inspirado en SonarQube, DefectDojo y SARIF.

La arquitectura MVC se conserva: los modelos pasan a ser SQLAlchemy, las vistas son los serializadores y la SPA, y los controladores siguen siendo blueprints finos sobre servicios. El plan tiene 9 fases (F0–F8), cada una con su criterio de terminado. Quedan seis decisiones abiertas para el usuario. La más importante es el hosting, porque de ella dependen la cookie de sesión, el worker y el coste.

**Cómo leer este documento.** Cada afirmación lleva una etiqueta:

| Etiqueta | Significado |
|---|---|
| **[H]** | Hecho con fuente citada en las notas de investigación. |
| **[C]** | Hecho del código actual, comprobado en la revisión directa de esta sesión. |
| **[D]** | Recomendación de diseño (inferencia mía, no un hecho). |

Las versiones de librerías que no aparecen en una fuente citada están marcadas como "a fijar". Nada de este plan instala ni ejecuta software sin la aprobación del usuario.

---

## 1. Las cuatro observaciones se resuelven con cuatro entregables medibles

| # | Observación del ingeniero | Causa raíz en el código actual | Respuesta del refactor | Requisitos | Fase |
|---|---|---|---|---|---|
| 1 | ¿Qué lo diferencia? ¿Cuál es su valor? | Sin propuesta escrita. La documentación es inconsistente: README v0.2.0 frente a pyproject 0.1.0, `./examples` frente a `samples/`, puerto 8000 frente a 5001 [C]. | Propuesta de valor acotada (sección 2), explicaciones didácticas por hallazgo, progreso entre escaneos y benchmark reproducible contra Bandit y Semgrep CE/Opengrep. | RF-03, RF-17, RF-18, RF-24, RF-26, RNF-02 | F0, F8 |
| 2 | ¿Cómo se integran las reglas? | `DEFAULT_RULES` fija con 12 clases. El `rule_id` cambia por sub-patrón (un `hashlib.md5` da dos IDs distintos). Cada regla taint vuelve a ejecutar el `TaintAnalyzer` completo (~5 veces por archivo). Las excepciones de las reglas se tragan en silencio. Solo hay taint intra-procedural, así que `request.args → helper(v) → os.system` sale como `DANGEROUS_FUNCTION`. Los secretos pasados como argumento no se detectan, y el auto-escaneo de `api/` da 0 hallazgos [C]. | Contrato `Rule`/`RuleMeta`/`FileContext`, registro con entry points, reglas YAML, una sola pasada AST y una sola pasada taint por archivo, `RuleError` visible, resúmenes de función, tests `# ruleid:` / `# ok:`. | RF-03 a RF-12, RNF-02, RNF-03, RNF-04 | F1, F2 |
| 3 | Infraestructura delicada | Desplegado en Vercel serverless con límites de 150 MB en el código. `CORS origins="*"`. `SECRET_KEY` y secreto JWT con valor de respaldo fijo. Dos usuarios demo con contraseña en el código. JWT de 24 h en `localStorage` y devuelto en la URL del callback OAuth. El `state` de OAuth se omite si falta. El `_engine` global se recrea por petición (condición de carrera). El ZIP se lee con `zf.read` sin tope total ni de número de entradas. Los errores devuelven el texto interno de la excepción. Todas las rutas se registran dos veces [C]. | Contenedor Docker con Gunicorn y un worker separado, configuración que falla al arrancar si falta un secreto, BFF con OIDC + PKCE, cookies `__Host-`, CSRF, CORS con lista blanca, cabeceras de seguridad, límites de ZIP, rate limiting, auditoría y errores genéricos. | RNF-01, RNF-04, RNF-06 | F3, F4, F5, F6 |
| 4 | No hay base de datos | El historial vive en `localStorage` (`sast.history.v1`) [C]. | PostgreSQL con `projects`, `scans`, `issues`, `occurrences`, `issue_events`, `sessions` y `audit_log`, migraciones con Alembic y fingerprint `sastfp/v1`. | RF-13 a RF-20, RNF-02, RNF-03 | F3 |

---

## 2. El valor está en enseñar en español y medir el progreso, no en detectar más

### 2.1 Qué se puede afirmar con respaldo

**El mercado gratuito ya está ocupado en la capa de detección.** Semgrep ofrece un plan Free de $0, con hasta 10 contribuidores, análisis cross-file, Pro rules y triage con IA. Por eso "gratis" por sí solo no diferencia [H] ([Semgrep Pricing](https://semgrep.dev/pricing)). SonarQube Community Build tiene dashboard self-hosted, pero **no incluye taint analysis**: el flujo de datos para inyecciones está en Developer Edition [H] ([Sonar Community](https://community.sonarsource.com/t/taint-analysis-capability/70624)). Horusec, que era el precedente de "orquestador SAST open source con dashboard", no publica tags desde junio de 2022 y tiene un issue abierto que pregunta si sigue mantenido [H] ([dev.co](https://dev.co/security/open-source/horusec); [ecosyste.ms](https://issues.ecosyste.ms/hosts/GitHub/repositories/ZupIT%2Fhorusec/issues)). Queda un hueco real pero estrecho: un dashboard self-hosted ligero, mantenido y centrado en enseñar seguridad [D].

**La literatura respalda centrarse en la explicación y no en el motor.** Johnson et al. (ICSE 2013) identifican los falsos positivos y la forma de presentar los avisos como frenos principales a la adopción del análisis estático [H] ([Google Research](https://research.google/pubs/pub43477/)). Incluso las herramientas maduras detectan poco en vulnerabilidades reales: 7 SAST de Java detectaron solo el **12,7%** de las CVE reales del benchmark de Li et al., FSE 2023 [H] ([Li et al.](https://kaixuanli-ecnu.github.io/papers/java-sast-fse23.pdf)). En Python el área está poco evaluada. Un estudio de ICSE 2026 partió precisamente de que esa capacidad no se había medido de forma exhaustiva [H] ([ICSE 2026](https://conf.researchr.org/details/icse-2026/icse-2026-research-track/30/An-Empirical-Study-on-Static-Application-Security-Testing-SAST-Tools-for-Python)). Por eso un mini-benchmark propio, pequeño y reproducible es un aporte más defendible que decir que el motor "detecta mejor" [D].

**Por qué conviene tener reglas propias.** Desde diciembre de 2024, las reglas mantenidas por Semgrep usan la "Semgrep Rules License v1.0", que limita su uso a contextos internos, no competidores y no SaaS [H] ([Semgrep docs](https://semgrep.dev/docs/faq/comparisons/opengrep)). Las reglas propias de SAST Studio (o las de Opengrep, con licencia LGPL 2.1 [H] ([InfoQ](https://www.infoq.com/news/2025/02/semgrep-forked-opengrep))) evitan ese conflicto si algún día se ofrece como servicio [D].

### 2.2 Propuesta de valor para el README y la presentación [D]

> SAST Studio es un analizador estático de seguridad **didáctico y self-hosted**. Cada hallazgo explica en español qué es, por qué es peligroso y cómo corregirlo, con un ejemplo vulnerable y otro corregido, y su mapeo a CWE y OWASP. Guarda el historial de cada proyecto para ver qué hallazgos son nuevos, cuáles se corrigieron y cuáles persisten. Se despliega con Docker + PostgreSQL sin enviar código a terceros, y sus reglas son pequeñas y legibles para estudiarlas o escribir nuevas.

### 2.3 Afirmaciones permitidas y prohibidas

| Se puede afirmar (verificable en el proyecto) [D] | No se debe afirmar [D, basado en H] |
|---|---|
| Explicación y corrección en español para cada regla, mapeada a CWE y OWASP Top 10. | Que detecta "más" o "mejor" que Semgrep, CodeQL, Sonar o Snyk. |
| Uso sin instalación: pegar código, subir un ZIP o indicar un repo público de GitHub. | Análisis semántico en JS/TS/PHP/Java/Go/C/C#: ahí solo hay regex por línea. Esas reglas deben etiquetarse como "heurísticas, confianza baja". |
| Self-hosted y gratuito (Docker + PostgreSQL); el código no sale del servidor. | Análisis cross-file. Tras F2 se podrá decir "inter-procedural **dentro del mismo archivo** en Python", y nada más. |
| Historial con nuevos, corregidos, persistentes y reabiertos, y MTTR por severidad. | Que cubre todo OWASP Top 10. Con 12 reglas no se cubre, y A04 Insecure Design no es detectable con SAST [D]. |
| SARIF 2.1.0, JSON y HTML, compatibles con GitHub Code Scanning y DefectDojo. | "Cero falsos positivos" o cualquier precisión que no se haya medido. |
| Taint intra-procedural real en Python, comparable a Bandit en ese aspecto concreto. | Apto para producción o cumplimiento normativo (PCI, ISO). |
| Precisión y recall medidos sobre un corpus anotado, con el script publicado (tras F8). | "El único SAST gratuito con dashboard" (existen SonarQube CE y Horusec) o "el único en español" (solo se puede decir que no se encontró otro). |

Falta un dato duro: no se encontraron encuestas que midan la barrera idiomática de estudiantes hispanohablantes con herramientas SAST. La necesidad de explicaciones en español se apoya en la experiencia docente, no en un estudio. Hay asignaturas que usan SAST de forma didáctica, por ejemplo en la Universidad de Cádiz [H] ([UCA](https://indoc.uca.es/memorias/sol-202400284950-tra.pdf)).

---

## 3. Requisitos numerados

### 3.1 Requisitos funcionales (RF)

**Convención de redacción.** Un requisito funcional describe **qué hace el sistema**; uno no funcional describe **cómo debe ser** (sus atributos de calidad) [H] ([Guru99](https://www.guru99.com/es/functional-vs-non-functional-requirements.html); [UNAD](https://repository.unad.edu.co/reproductor-ova/10596_35614/tipos_de_requerimientos.html)). Por eso cada RF sigue la plantilla **"El sistema debe + verbo en infinitivo + objeto"**, con un solo requisito por fila y un criterio verificable, como pide la guía de calidad de requisitos de ISO/IEC/IEEE 29148 [H] ([IEC, vista previa 29148](https://webstore.iec.ch/p-preview/info_isoiecieee29148%7Bed1.0%7Den.pdf); [NASA SWE Handbook](https://swehb.nasa.gov/x/XQFiC)). Todos son **[D]**; cuando un RF corrige un defecto observado, se indica con [C].

| ID | Requisito | Criterio de aceptación |
|---|---|---|
| **RF-01** | El sistema debe **recibir** código para escanear desde tres entradas: texto pegado (≤ 1 MB), archivo ZIP y repositorio público de GitHub (`owner/repo[@ref]`). | Las tres crean un `scan` en estado `queued` y devuelven 202. |
| **RF-02** | El sistema debe **identificar** el lenguaje de cada archivo por su extensión y **marcar** los hallazgos de lenguajes analizados por regex con `confidence=LOW` y `engine=heuristic`. | La UI y el SARIF muestran el motor y la confianza. |
| **RF-03** | El sistema debe **listar** el catálogo de reglas con sus metadatos: `id` estable (`py/weak-hash`), nombre, mensaje, severidad, confianza, CWE, OWASP, `kind`, `security_severity` 0–10, `previous_ids`, referencias, explicación en español y ejemplos vulnerable y corregido. | `GET /api/v1/rules` devuelve las 12 reglas migradas con todos los campos; un test falla si falta alguno. |
| **RF-04** | El sistema debe **cargar** reglas declarativas YAML desde un directorio sin modificar el motor. | Se añade un `.yaml` con su test y la regla aparece y pasa sin cambiar código Python. |
| **RF-05** | El sistema debe **registrar** reglas Python externas como plugins mediante `@register` y el entry point `sast_studio.rules`. | Un paquete de ejemplo registra una regla. |
| **RF-06** | El sistema debe **suprimir** los hallazgos marcados en el código con `# sast: ignore[id] reason: ...` o `# nosec`, **conservándolos** con `suppressed=true` y el motivo. | El SARIF los exporta en `suppressions[{kind:"inSource"}]`. |
| **RF-07** | El sistema debe **reportar** un único hallazgo por (regla, ubicación), guardando el sub-patrón en `variant` y no en el ID. | `hashlib.md5(x)` produce **un** hallazgo `py/weak-hash` con `variant=md5` (hoy produce dos [C]). |
| **RF-08** | El sistema debe **informar** cada fallo de una regla como `RuleError` (regla, archivo, tipo, mensaje) en la salida, la UI y el SARIF, y **terminar** con error en la CLI si se usa `--fail-on-rule-error`. | Una regla que lanza excepción no oculta los hallazgos de las demás y aparece en el resumen. |
| **RF-09** | El sistema debe **rastrear** datos contaminados entre funciones del mismo archivo mediante resúmenes de función. | `request.args → helper(v) → os.system` produce `py/command-injection` con traza (hoy sale `DANGEROUS_FUNCTION` [C]). |
| **RF-10** | El sistema debe **detectar** secretos pasados como argumentos: valor por defecto de `os.environ.get`/`getenv` y literales de alta entropía o con nombre sensible. | El auto-escaneo de `api/` detecta el fallback de `JWT_SECRET` y `_demo_pw("Admin123!")` (hoy da 0 [C]). |
| **RF-11** | El sistema debe **generar** informes SARIF 2.1.0, JSON y HTML; el SARIF incluye `ruleId` estable, `partialFingerprints`, `baselineState` y `suppressions`. | Valida contra el esquema SARIF; dos escaneos iguales subidos a GitHub no duplican alertas. |
| **RF-12** | El sistema debe **ofrecer** una CLI (`sast scan`, `rules`, `test-rules`, `bench`) que use el mismo registro y runner que la API. | Para la misma entrada, CLI y API dan los mismos fingerprints. |
| **RF-13** | El sistema debe **permitir** al usuario crear, listar, renombrar y eliminar proyectos, y **asociar** cada escaneo a un proyecto (el código pegado va a "Borradores"). | Pruebas BOLA (RNF-01). |
| **RF-14** | El sistema debe **ejecutar** los escaneos en segundo plano con estados `queued → running → done | failed | canceled`, **mostrar** su progreso y **permitir** cancelarlos. | `POST /scans/{id}/cancel` detiene el escaneo en ≤ 1 archivo o al vencer el tiempo límite. |
| **RF-15** | El sistema debe **mantener** un issue persistente por fingerprint y proyecto, y **actualizar** automáticamente su estado `open → fixed → reopened`. | Mover el código 20 líneas no duplica el issue. |
| **RF-16** | El sistema debe **permitir** clasificar cada issue (`confirmed`, `false_positive`, `accepted`, `wont_fix`), **exigir** justificación salvo en `confirmed` y **conservar** la clasificación en escaneos posteriores. | Un falso positivo marcado no reaparece como abierto. |
| **RF-17** | El sistema debe **comparar** dos escaneos del mismo proyecto y **mostrar** hallazgos nuevos, persistentes, corregidos y reabiertos. | Coincide con el `baselineState` del SARIF. |
| **RF-18** | El sistema debe **calcular** por proyecto: abiertos por severidad en el tiempo, nuevos frente a corregidos, MTTR por severidad y densidad por KLOC, excluyendo falsos positivos. | Endpoint `metrics` y gráficas en la UI. |
| **RF-19** | El sistema debe **registrar** el historial de cada issue (cambios de estado, triage, comentarios) con su autor y fecha. | `GET /issues/{id}/events`. |
| **RF-20** | El sistema debe **eliminar** en cascada los escaneos, ocurrencias y fragmentos de un proyecto borrado, y **purgar** las ocurrencias de escaneos con más de 90 días (configurable) conservando sus resúmenes. | Test de borrado en cascada y evento de auditoría `data.delete`. |
| **RF-21** | El sistema debe **autenticar** al usuario con Google (OIDC), **cerrar** su sesión y **devolver** sus datos en `GET /auth/me`. | Flujo E2E en el entorno de pruebas. |
| **RF-22** | El sistema debe **habilitar** un acceso de desarrollo solo con `ENVIRONMENT=dev` y `DEV_LOGIN_ENABLED=true`, y **rechazar** el arranque si se activa en producción. | Test de configuración; se eliminan los usuarios demo con contraseña fija [C]. |
| **RF-23** | El sistema debe **guardar** el historial de escaneos en el servidor y **mostrarlo** en las pantallas de la sección 4.4. | No queda ningún dato de escaneo en `localStorage`. |
| **RF-24** | El sistema debe **explicar** cada hallazgo en español: qué es, por qué es peligroso, ejemplo vulnerable y corregido, cómo corregirlo y enlaces CWE/OWASP. | Las 12 reglas tienen la explicación completa, revisada por una persona. |
| **RF-25** | El sistema debe **exportar** el informe de un escaneo en SARIF, JSON o HTML desde la UI y la API. | Descarga con `Content-Disposition`. |
| **RF-26** | El sistema debe **medir** la precisión y el recall de cada regla sobre el corpus anotado (`sast bench`) y **compararlos** con Bandit y Semgrep CE/Opengrep si están instalados. | Tabla reproducible en `docs/benchmark.md`; las cifras del README salen solo de ahí. |

### 3.2 Requisitos no funcionales (RNF)

**Convención de redacción.** Cada RNF es una **propiedad del sistema** y agrupa, en un solo requisito, todo lo que corresponde a una característica de calidad de **ISO/IEC 25010** [H] ([UNAD](https://repository.unad.edu.co/reproductor-ova/10596_35614/tipos_de_requerimientos.html); [NASA SWE Handbook](https://swehb.nasa.gov/x/XQFiC)). El detalle técnico (valores exactos, librerías) está en las fases de la sección 5. **Nivel objetivo de seguridad: OWASP ASVS 5.0 Nivel 2** (inferencia: la app autentica usuarios y guarda código subido) [H] ([ASVS V10](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x19-V10-OAuth-and-OIDC.md); [ASVS V16](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)).

| ID | Característica | Requisito | Cómo se verifica |
|---|---|---|---|
| **RNF-01** | **Seguridad** | El sistema debe ser seguro según OWASP ASVS 5.0 nivel 2: secretos solo desde el entorno y sin valores por defecto; sesión en el servidor con cookie `HttpOnly`/`Secure`/`SameSite=Strict` (sin tokens en URL ni `localStorage`); login con Google mediante PKCE, `state` y `nonce` que falla cerrado; protección CSRF; web y API en el mismo origen sin CORS abierto; cabeceras de seguridad; errores genéricos sin detalles internos; cada usuario solo accede a sus propios datos (404 en recursos ajenos); ZIPs y descargas de GitHub con límites de tamaño, número de archivos y compresión; el código subido nunca se ejecuta y se borra al terminar el escaneo; auditoría de solo inserción; sin cuentas por defecto. | Tests automáticos de arranque sin secretos, CSRF, OIDC, BOLA, zip bomb/zip slip y cabeceras; checklist ASVS (IDs principales: 3.4.2, 3.5.1–3.5.3, 5.2.3, 6.3.2, 8.2.2, 10.1.1–10.5.4, 13.3.1, 14.2.1, 14.3.3, 16.3.1–16.5.4; API Top 10: API1, API4, API7, API8). |
| **RNF-02** | **Mantenibilidad** | El sistema debe ser fácil de modificar y probar: arquitectura MVC con capa de servicios (controladores finos, sin acceso directo a la BD); motor construido por escaneo, nunca global; esquema versionado con migraciones Alembic; cada regla con al menos un verdadero positivo y un verdadero negativo anotados; documentación coherente con el código y una sola fuente de versión. | Cobertura ≥ 80 % en `sast/` y `api/services/`; `alembic upgrade`/`downgrade` en CI; lint y tipos sin errores; README revisado en F0. |
| **RNF-03** | **Eficiencia de desempeño** | El sistema debe responder rápido y usar recursos de forma acotada: la API encola el escaneo sin esperar al análisis; el motor analiza cada archivo una sola vez (un AST y una pasada de taint compartidos por todas las reglas); el pool de conexiones a Postgres está limitado. | `POST /scans` responde 202 en < 1 s (p95); tiempo por KLOC medido en F8 (meta: ≤ 1/3 del motor actual); `workers × conexiones` < límite de Postgres. |
| **RNF-04** | **Fiabilidad** | El sistema debe ser estable y predecible: cada escaneo corre aislado con tiempo límite y su fallo no afecta a la API; límites de uso por IP y por usuario contra abusos; resultados deterministas; estado expuesto para que el orquestador reinicie el servicio si falla. | Un escaneo que supera 300 s termina como `failed`; exceso de peticiones → 429; dos ejecuciones iguales dan el mismo SARIF; `/healthz` y `/readyz` responden. |
| **RNF-05** | **Usabilidad** | La interfaz debe ser accesible, en español y con aspecto de herramienta profesional (basada en un sistema de diseño probado, sin patrones típicos de IA). | Auditoría WCAG 2.1 AA sin errores; revisión con las guías de Vercel y capturas por pantalla (sección 4.4). |
| **RNF-06** | **Portabilidad** | El sistema debe poder instalarse igual en cualquier máquina: imagen Docker multi-stage con usuario no root y `HEALTHCHECK`; dependencias en un solo `pyproject.toml` con versiones fijadas (hoy hay dos `requirements.txt` [C]). | `docker compose up` levanta API, worker y Postgres en una máquina limpia con las mismas versiones. |

---

## 4. Contratos de interfaz

### 4.1 API REST `/api/v1` [D]

**Convenciones generales:**

- **Autenticación:** "Sesión" significa la cookie `__Host-sast_session` válida. "CSRF" significa que el método no es seguro y exige `Origin` permitido + `X-CSRF-Token`.
- **Errores:** `{"error":{"code":"not_found","message":"Recurso no encontrado","request_id":"..."}}`.
- **Paginación:** `?limit=50&cursor=<opaco>`. La respuesta tiene la forma `{"items":[...],"next_cursor":...}`.
- **Fechas:** ISO-8601 en UTC.
- **Prefijo:** se elimina el registro duplicado `/x` + `/api/x` actual [C]. Durante una versión se mantienen alias `/api/*` que responden `308` hacia `/api/v1/*`.

| Método | Ruta | Auth | Petición | Respuesta | Códigos |
|---|---|---|---|---|---|
| GET | `/healthz` | — | — | `{"status":"ok"}` | 200 |
| GET | `/readyz` | — | — | `{"db":"ok","migrations":"head"}` | 200, 503 |
| GET | `/api/v1/auth/login` | — | `?next=/ruta` (solo rutas relativas en la lista blanca) | Redirección a Google con state, nonce y PKCE. Fija `__Host-sast_login`. | 302, 429 |
| GET | `/api/v1/auth/callback` | cookie de login | `?code&state` (de Google) | Crea la sesión, fija `__Host-sast_session`, borra la cookie de login y redirige a la ruta fija de la SPA **sin token**. Lleva `Referrer-Policy: no-referrer`. | 302, 400 |
| POST | `/api/v1/auth/logout` | Sesión + CSRF | — | Revoca la sesión y borra la cookie. | 204, 401, 403 |
| GET | `/api/v1/auth/me` | Sesión | — | `{"id","email","name","csrf_token"}` | 200, 401 |
| GET | `/api/v1/rules` | Sesión | `?language=python&severity=HIGH` | `[{id,name,severity,confidence,cwe[],owasp[],kind,languages[],engine,explanation_es,example_bad,example_good,references[]}]` | 200, 401 |
| GET | `/api/v1/rules/{rule_id}` | Sesión | — | Regla completa. | 200, 404 |
| GET | `/api/v1/projects` | Sesión | paginación | `{items:[{id,name,created_at,last_scan:{id,status,finished_at,summary}}]}` | 200, 401 |
| POST | `/api/v1/projects` | Sesión + CSRF | `{"name": str(1..120)}` | Proyecto creado. | 201, 400, 401, 403, 409 |
| GET | `/api/v1/projects/{pid}` | Sesión | — | Proyecto con conteos de issues abiertos por severidad. | 200, 404 |
| PATCH | `/api/v1/projects/{pid}` | Sesión + CSRF | `{"name"}` | Proyecto actualizado. | 200, 400, 404 |
| DELETE | `/api/v1/projects/{pid}` | Sesión + CSRF | — | Borrado en cascada (RF-20). | 204, 404 |
| POST | `/api/v1/projects/{pid}/scans` | Sesión + CSRF | `multipart/form-data` con `file` (.zip ≤ 25 MB), **o** JSON `{"source":"snippet","filename":"app.py","code":str}`, **o** JSON `{"source":"github","repo":"owner/repo","ref":"main"}`. Opcional: `rules` (lista de IDs) y `category`. | `{"id","status":"queued"}` + `Location: /api/v1/scans/{id}` | 202, 400, 404, 413, 415, 422, 429 |
| GET | `/api/v1/projects/{pid}/scans` | Sesión | paginación | Lista de escaneos con `summary`. | 200, 404 |
| GET | `/api/v1/scans/{sid}` | Sesión | — | `{id,project_id,status,progress:{files_done,files_total},started_at,finished_at,summary:{by_severity,new,fixed,persisting,reopened},rule_errors:[...],error_code}` | 200, 404 |
| POST | `/api/v1/scans/{sid}/cancel` | Sesión + CSRF | — | `{"status":"canceling"}` | 202, 404, 409 (ya terminado) |
| GET | `/api/v1/scans/{sid}/findings` | Sesión | `?severity&rule_id&path&change=new|persisting|reopened&triage&limit&cursor` | `{items:[{occurrence_id,issue_id,rule_id,severity,confidence,path,start_line,end_line,message,snippet,trace:[{line,desc}],change,triage,suppressed}]}` | 200, 404 |
| GET | `/api/v1/scans/{sid}/diff` | Sesión | `?base=<sid>` (por defecto, el escaneo anterior del mismo flujo) | `{new:[...],fixed:[...],persisting_count,reopened:[...]}` | 200, 404, 422 (flujos distintos) |
| GET | `/api/v1/scans/{sid}/report` | Sesión | `?format=sarif|json|html` | Archivo con `Content-Disposition: attachment` | 200, 404, 409 (no terminado) |
| GET | `/api/v1/projects/{pid}/issues` | Sesión | `?lifecycle=open|fixed|reopened&triage&severity&rule_id&path` | Issues con `first_seen_at`, `last_seen_scan_id` y ubicación actual. | 200, 404 |
| GET | `/api/v1/issues/{iid}` | Sesión | — | Issue + última ocurrencia + regla. | 200, 404 |
| PATCH | `/api/v1/issues/{iid}` | Sesión + CSRF | `{"triage":"false_positive","justification":str(≤2000)}` | Issue actualizado y evento creado. | 200, 400, 404, 422 (falta la justificación) |
| GET | `/api/v1/issues/{iid}/events` | Sesión | — | `[{kind,from,to,user,comment,created_at}]` | 200, 404 |
| POST | `/api/v1/issues/{iid}/comments` | Sesión + CSRF | `{"body":str(≤2000)}` | Evento creado. | 201, 400, 404 |
| GET | `/api/v1/projects/{pid}/metrics` | Sesión | `?from&to` | `{open_by_severity:[{scan_id,date,critical,high,medium,low}],new_vs_fixed:[...],mttr_days:{high:{median,mean},...},density_per_kloc}` | 200, 404 |

Los códigos 401 (sin sesión), 403 (fallo de CSRF u origen), 429 y 500 genérico aplican a todos los endpoints con sesión. El 404 es deliberado en recursos ajenos (RNF-01).

**Estado del escaneo:** se consulta por polling (`GET /scans/{id}` cada 1–2 s con backoff). Se descarta SSE porque mantiene conexiones largas que ocupan workers sync de Gunicorn y que los proxies PaaS pueden cortar [D, con base en H ([Gunicorn](https://gunicorn.org/reference/settings/))].

### 4.2 Interfaz del motor de reglas

**Diseño [D]**, construido con patrones documentados: el `context` precomputado de Bandit, los IDs inmutables con `@test.test_id`, el despacho por tipo de nodo con `@test.checks("Call")` [H] ([Bandit plugins](https://bandit.readthedocs.io/en/latest/plugins/index.html)), el metadato `@id`/`@kind`/`@precision`/`@security-severity` de CodeQL [H] ([CodeQL style guide](https://github.com/github/codeql/blob/main/docs/query-metadata-style-guide.md)) y el descubrimiento por entry points de PyPA [H] ([PyPA](https://packaging.python.org/en/latest/guides/creating-and-discovering-plugins/)).

```python
# sast/rules/api.py  (nuevo; sustituye a BaseRule y _make_finding)
from __future__ import annotations
import ast
from dataclasses import dataclass
from enum import IntEnum
from functools import cached_property
from typing import Iterable, Protocol

class Severity(IntEnum):   LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4   # ordenable
class Confidence(IntEnum): LOW = 1; MEDIUM = 2; HIGH = 3

@dataclass(frozen=True)
class RuleMeta:                       # inmutable: el id NO cambia por sub-patrón
    id: str                           # "py/weak-hash"  (prefijo de lenguaje + sustantivo)
    name: str
    message: str                      # admite {variant}, {source}, {sink}
    severity: Severity
    confidence: Confidence
    languages: tuple[str, ...]
    cwe: tuple[str, ...] = ()         # ("CWE-327",)
    owasp: tuple[str, ...] = ()       # ("A02:2021",)
    kind: str = "problem"             # "problem" | "path-problem" (taint)
    engine: str = "ast"               # "ast" | "taint" | "heuristic" (regex)
    security_severity: float | None = None   # 0-10; nivel por bandas CVSS
    previous_ids: tuple[str, ...] = ()       # renombres: mantiene baseline/supresiones
    supersedes: tuple[str, ...] = ()         # oculta la regla genérica en el mismo span
    references: tuple[str, ...] = ()
    doc_es: str = ""                  # ruta a docs/rules/<id>.md (qué es / por qué / cómo corregir)

@dataclass(frozen=True)
class Finding:
    rule_id: str
    path: str                         # relativo a la raíz del proyecto, con "/"
    line: int; col: int; end_line: int; end_col: int
    message: str
    severity: Severity
    confidence: Confidence
    trace: tuple[tuple[int, str], ...] = ()   # (línea, descripción) en path-problem
    variant: str | None = None                # "md5" / "sha1": dato, NO otro id
    suppressed: bool = False
    suppression_reason: str | None = None

class FileContext:
    """Uno por archivo. Cada análisis caro se calcula una vez, de forma perezosa, y se comparte."""
    def __init__(self, path: str, source: str, language: str, taint_models: "TaintModels"): ...
    @cached_property
    def tree(self) -> ast.Module | None: ...          # None si no es Python o no parsea
    @cached_property
    def lines(self) -> list[str]: ...
    @cached_property
    def imports(self) -> dict[str, str]: ...         # alias -> nombre calificado
    @cached_property
    def call_graph(self) -> "CallGraph": ...
    @cached_property
    def summaries(self) -> dict[str, "Summary"]: ... # resúmenes de función (F2)
    @cached_property
    def taint(self) -> "TaintResult": ...            # UNA pasada; .flows[(sink_kind)] -> [Flow]
    @cached_property
    def suppressions(self) -> dict[int, set[str] | None]: ...  # línea -> ids (None = todas)
    def qualname(self, node: ast.Call) -> str | None: ...       # "hashlib.md5", resolviendo alias

class Rule(Protocol):
    meta: RuleMeta
    node_types: tuple[type[ast.AST], ...]            # () = regla de archivo completo
    def check(self, ctx: FileContext, node: ast.AST | None) -> Iterable[Finding]: ...

@dataclass(frozen=True)
class RuleError:
    rule_id: str; path: str; exc_type: str; message: str   # el traceback va solo al log
```

**Registro y carga [D].** Archivo `sast/rules/registry.py`:

- `register(cls)` lanza `ValueError` si el ID está duplicado.
- `load_builtin()` importa `sast.rules.builtin.*`.
- `load_plugins()` recorre `importlib.metadata.entry_points(group="sast_studio.rules")` y anota `LOAD_ERRORS` sin abortar.
- `load_yaml_dir(path)` valida cada archivo con un modelo pydantic y lo compila a `DeclarativeRule`, que implementa el mismo protocolo `Rule`.
- `RuleSet.select(ids|languages|min_confidence)` filtra.

El registro es **inmutable tras la carga**. Cada escaneo construye su propio `Engine(ruleset, config)`, lo que elimina la condición de carrera del `_engine` global [C].

**Runner [D].** Archivo `sast/engine/runner.py`:

1. Para cada archivo construye un `FileContext`.
2. Agrupa las reglas por `node_types` y recorre el AST **una vez** con `ast.walk`.
3. Llama a cada regla dentro de su propio `try/except`, que acumula `RuleError`.
4. Ejecuta las reglas de archivo completo y las regex.
5. Aplica supresiones (marca, no borra).
6. Deduplica por `(rule_id, path, line, col, end_line, end_col)` quedándose con la mayor `(confidence, severity)`.
7. Aplica `supersedes`.
8. Ordena por `(path, line, col, rule_id)`.

Las reglas taint no recalculan nada: filtran `ctx.taint.flows` por los `sink_kinds` que declaran. Eso elimina las ~5 pasadas por archivo actuales [C].

**Formato YAML de reglas.** Es un subconjunto de la sintaxis de Semgrep. Semgrep exige `id`, `message`, `severity` y `languages` más una fórmula de patrones, usa severidades `LOW|MEDIUM|HIGH|CRITICAL` y declara las reglas taint con `mode: taint` y `pattern-sources`/`pattern-sinks`/`pattern-sanitizers` [H] ([Semgrep rule syntax](https://docs.semgrep.dev/writing-rules/rule-syntax); [taint mode](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview)). El subconjunto que propongo, mapeado a `ast` de Python, es [D]:

```yaml
# sast/rules/yaml/python/weak-hash.yaml
rules:
  - id: py/weak-hash
    name: Hash criptográfico débil
    message: "Se usa {variant} con fines de seguridad. Usa hashlib.sha256 o usedforsecurity=False."
    severity: MEDIUM
    confidence: HIGH
    languages: [python]
    engine: ast
    metadata:
      cwe: ["CWE-327"]
      owasp: ["A02:2021"]
      security_severity: 5.9
      references: ["https://docs.python.org/3/library/hashlib.html"]
      doc_es: docs/rules/py-weak-hash.md
    match:                      # AND implícito
      call-either:              # OR; cada alternativa informa bajo el MISMO id
        - call: "hashlib.$ALG"
        - call: "hashlib.new"
          arg0: "$ALG"
      where:
        - metavar-regex: { $ALG: "(?i)^(md5|sha1)$" }
      not:
        - kwarg: { usedforsecurity: false }
    variant: $ALG
```

```yaml
# sast/rules/yaml/python/command-injection.yaml  (taint: solo declara tipos de sink)
rules:
  - id: py/command-injection
    name: Inyección de comandos del sistema
    message: "Una entrada de {source} llega a un comando del sistema ({sink})."
    severity: HIGH
    confidence: MEDIUM
    languages: [python]
    engine: taint
    kind: path-problem
    metadata: { cwe: ["CWE-78"], owasp: ["A03:2021"], security_severity: 9.8 }
    taint:
      sinks: [shell]            # remite a sast/taint/models.yaml
    supersedes: [py/dangerous-function]
```

```yaml
# sast/taint/models.yaml  (fuente única de fuentes/sinks/sanitizadores, al estilo Pysa)
sources:
  http_input: ["flask.request.args.get", "flask.request.form.get", "flask.request.get_json", "input"]
sinks:
  shell: [{call: "os.system", arg: 0}, {call: "subprocess.*", kwarg: {shell: true}, arg: 0}]
  sql:   [{call: "*.execute", arg: 0}]
sanitizers:
  shell: ["shlex.quote"]
unknown_callee: propagate_args_to_return     # por defecto conservador de Pysa
```

El modelo de Pysa declara fuentes y sinks por nombre calificado, infiere modelos para cada función y supone que las funciones desconocidas propagan la contaminación de los argumentos al retorno [H] ([Pysa basics](https://pyre-check.org/docs/pysa-basics/)). Los resúmenes `Summary{param_to_return, param_to_sink, returns_source, sanitizes}` se calculan en orden topológico inverso del grafo de llamadas, con punto fijo para la recursión, dentro de `FileContext.summaries` [D]. Con eso se resuelve RF-09.

**Tests de reglas.** Siguen la convención de Semgrep: `# ruleid: <id>` encima de la línea que debe disparar, `# ok: <id>` encima de la que no, y `todoruleid` / `todook` para falsos negativos y positivos conocidos que no hacen fallar el test [H] ([Semgrep testing](https://docs.semgrep.dev/writing-rules/testing-rules)). El arnés sería `tests/rules/test_annotations.py`, unas 50 líneas de pytest que comparan conjuntos `(rule_id, línea)`, con un archivo de casos por regla en `tests/rules/cases/<id>.py` [D]. Los casos de la revisión de esta sesión (interprocedural, secretos como argumento, MD5 duplicado, MD5 no criptográfico) entran en F0 como `todoruleid` / `todook` y pasan a `ruleid` / `ok` cuando se arreglen.

**Supresión:** `# sast: ignore[py/weak-hash] reason: checksum`. También se acepta `# nosec` / `# nosec B324`, como en Bandit [H] ([Bandit config](https://bandit.readthedocs.io/en/latest/config.html)). Igual que Semgrep, el hallazgo se conserva marcado como ignorado [H] ([Semgrep ignoring](https://docs.semgrep.dev/ignoring-files-folders-code)).

### 4.3 Esquema PostgreSQL

**Principios:**

- Un **issue persistente** por fingerprint y proyecto, y una **ocurrencia** por escaneo. Es el modelo de SonarQube, no el de DefectDojo, que crea un Finding por Test con duplicados que apuntan a un original [D].
- **Ciclo de vida** (lo decide el sistema) separado del **triage** (lo deciden las personas). Así se evitan los booleanos combinables de DefectDojo. Su PR #12291 documenta que el reimport podía perder estados de falso positivo o riesgo aceptado [H] ([DefectDojo PR #12291](https://github.com/DefectDojo/django-DefectDojo/pull/12291)).
- SonarQube reabre automáticamente los Fixed que no son FP cuando vuelven a detectarse [H] ([SonarQube 10.4](https://docs.sonarsource.com/sonarqube-server/10.4/user-guide/issues)).

Las tablas, todas con PK `uuid` salvo indicación [D]:

| Tabla | Columnas clave | Estados / restricciones | Índices |
|---|---|---|---|
| `users` | `id`, `google_sub` UNIQUE, `email`, `name`, `created_at`, `disabled_at` | Se identifica por `sub`, no por email. | — |
| `sessions` | `id`, `user_id` FK, `token_hash` char(64) UNIQUE, `csrf_secret`, `created_at`, `last_seen_at`, `expires_at`, `revoked_at`, `ip`, `user_agent` | Válida si `revoked_at IS NULL` y no ha vencido ni por inactividad ni por tiempo absoluto. | `(user_id)`, `(expires_at)` |
| `projects` | `id`, `owner_id` FK, `name`, `created_at`, `deleted_at` | UNIQUE `(owner_id, name)` | `(owner_id)` |
| `rules` | `id` text PK (`py/weak-hash`), `tool` (`sast-studio`), `name`, `default_severity` smallint, `confidence`, `cwe` text[], `owasp` text[], `kind`, `engine`, `previous_ids` text[], `meta` jsonb, `version` | Se sincroniza desde el registro al arrancar el worker. | — |
| `scans` | `id`, `project_id` FK ON DELETE CASCADE, `created_by`, `source` (`snippet|zip|github`), `source_ref` (repo@ref o nombre de archivo), `category` (flujo comparable), `commit_sha`, **`status`**, `progress_done`, `progress_total`, `attempts`, `cancel_requested` bool, `heartbeat_at`, `worker_id`, `queued_at`, `started_at`, `finished_at`, `error_code`, `rules_enabled` text[], `engine_version`, `loc_total`, `files_scanned`, `summary` jsonb, `rule_errors` jsonb, `baseline_scan_id` FK, `request_id` | `status ∈ {queued, running, done, failed, canceled}` (VARCHAR + CHECK, `Enum(native_enum=False)`) | `(status, queued_at)` parcial `WHERE status='queued'`; `(project_id, category, finished_at DESC)` |
| `scan_uploads` | `scan_id` PK/FK CASCADE, `content` bytea (≤ 25 MB), `sha256`, `size`, `created_at` | Se borra en el `finally` del worker. Una purga elimina las de más de 1 h. | — |
| `issues` | `id`, `project_id` FK CASCADE, `rule_id` FK, `fingerprint` char(64), `fingerprint_version` smallint, **`lifecycle`**, **`triage`**, `triage_justification`, `severity` smallint, `current_path`, `first_seen_scan_id`, `last_seen_scan_id`, `first_seen_at`, `fixed_at`, `reopened_count`, `assignee_id` | `lifecycle ∈ {open, fixed, reopened}`; `triage ∈ {untriaged, confirmed, false_positive, accepted, wont_fix}`; UNIQUE `(project_id, fingerprint_version, fingerprint)` | `(project_id, lifecycle, severity)`; parcial `WHERE lifecycle <> 'fixed'` |
| `occurrences` | `id`, `scan_id` FK CASCADE, `issue_id` FK CASCADE, `path`, `start_line`, `end_line`, `start_col`, `message`, `snippet` text (≤ 4 KB, redactado), `line_hash`, `trace` jsonb, `variant`, `suppressed`, `suppression_reason`, `change` (`new|persisting|reopened`) | UNIQUE `(scan_id, issue_id)` | `(scan_id)`, `(issue_id)` |
| `issue_events` | `id` bigserial, `issue_id` FK CASCADE, `user_id` NULL (sistema), `kind` (`lifecycle|triage|comment`), `from_state`, `to_state`, `comment`, `scan_id`, `created_at` | Solo inserción. | `(issue_id, created_at)` |
| `audit_log` | `id` bigserial, `at` timestamptz, `event`, `user_sub`, `ip`, `user_agent`, `request_id`, `target_type`, `target_id`, `outcome`, `details` jsonb | Solo inserción. `REVOKE UPDATE, DELETE` al rol de la app. | `(at)`, `(user_sub, at)` |

**Cola de trabajos en la propia tabla `scans` [D].** PostgreSQL documenta que `SKIP LOCKED` sirve "para evitar la contención de bloqueos con varios consumidores accediendo a una tabla tipo cola" [H] ([PostgreSQL SELECT](https://www.postgresql.org/docs/current/sql-select.html)). El worker reclama trabajos con:

```sql
UPDATE scans SET status='running', started_at=now(), heartbeat_at=now(), worker_id=:w, attempts=attempts+1
WHERE id = (SELECT id FROM scans WHERE status='queued' ORDER BY queued_at
            FOR UPDATE SKIP LOCKED LIMIT 1)
RETURNING *;
```

Un "reaper" devuelve a `queued` los trabajos cuyo `heartbeat_at` tenga más de 2 minutos si `attempts < 3`, y los demás los marca `failed` (`error_code='worker_lost'`).

**Algoritmo de fingerprint `sastfp/v1` [D].** Está inspirado en dos precedentes. GitHub excluye el número de línea, hashea una ventana de 100 caracteres no blancos desde la línea inicial y añade `:N` por ocurrencia [H] ([codeql-action fingerprints.ts](https://raw.githubusercontent.com/github/codeql-action/main/src/fingerprints.ts)). SonarQube empareja por regla + hash de línea sin espacios [H] ([SonarQube 10.4](https://docs.sonarsource.com/sonarqube-server/10.4/user-guide/issues)).

```text
norm_path   = ruta relativa a la raíz del proyecto, separador "/", sin "./" inicial,
              sin prefijos temporales ni de zipball ("owner-repo-<sha>/")
norm_code   = líneas [start_line..end_line] (máx. 3) + 1 línea de contexto si la línea normalizada
              tiene < 12 caracteres; CRLF→LF; se elimina TODO espacio en blanco;
              en reglas de secretos, el contenido de literales de cadena se sustituye por "S"
snippet_hash= sha256(norm_code)
occurrence  = rango 1..n entre hallazgos con igual (rule_id, norm_path, snippet_hash), ordenados por línea
fingerprint = sha256("v1|sast-studio|" + canonical_rule_id + "|" + norm_path + "|" + snippet_hash + "|" + occurrence)
```

`canonical_rule_id` es el ID actual. Si un issue antiguo tiene un ID de `previous_ids`, se reconoce en la fase 2 del emparejador. Lo que queda fuera del hash: el número de línea, la columna, el mensaje, la ruta absoluta y la versión del escaneador. Si el algoritmo cambia, se sube `fingerprint_version` en lugar de cambiar la normalización en silencio. DefectDojo advierte que sus cambios de hash no se aplican retroactivamente [H] ([DefectDojo](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/finding/models.py)).

**Emparejador multipaso [D]**, aplicado por proyecto y flujo (`category`):

1. Fingerprint exacto.
2. (regla o `previous_ids`, `norm_path`, `line_hash`) sin ocurrencia.
3. (regla, `norm_path`, mensaje, línea ±3).
4. (regla, `snippet_hash`) en otro archivo, para detectar renombres.

Luego se actualiza el ciclo de vida:

- Un issue `open` o `reopened` sin ocurrencia en el escaneo actual pasa a `fixed`, con `fixed_at = finished_at`, **solo si su regla estaba en `rules_enabled`** y su archivo dentro del alcance. Así se evita que desactivar una regla cuente como "corregido" [D].
- Un issue `fixed` que vuelve a aparecer pasa a `reopened`, salvo que tenga `triage=false_positive`.
- El triage nunca lo cambia el sistema.

**Diff y métricas.** "Corregidos" es un anti-join de las ocurrencias del escaneo base frente a las del actual. El MTTR se calcula con `percentile_cont(0.5)` sobre `fixed_at - first_seen_at` por severidad, excluyendo FP. Algunos proveedores recomiendan la mediana porque la media mezclada oculta el rendimiento en severidad crítica [H] ([Endor Labs](https://www.endorlabs.com/learn/mean-time-to-remediate-mttr)).

**En SARIF:**

- `partialFingerprints["sastStudio/v1"] = fingerprint`.
- `baselineState`: `new` / `unchanged` / `absent`, según la semántica de SARIF 2.1.0 [H] ([OASIS SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)).
- `primaryLocationLineHash` lo completa `upload-sarif` de GitHub, que solo empareja con ese valor; si falta, se duplican alertas [H] ([GitHub SARIF support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)). Por eso el CI debe subir con la acción oficial y no directamente por la API [D].

**Retención [D].** `issues` e `issue_events` se conservan indefinidamente porque son pequeños y hacen falta para el MTTR. Las `occurrences` de escaneos con más de 90 días se purgan, conservando `scans.summary`. SonarQube purga por defecto los Fixed tras 30 días [H] ([SonarQube 10.4](https://docs.sonarsource.com/sonarqube-server/10.4/user-guide/issues)); aquí se prefiere no purgar issues para no romper las métricas de largo plazo.

### 4.4 Interfaz visual que no parezca hecha por IA

**Diagnóstico.** La evidencia es anecdótica: no hay comparaciones controladas. La conclusión recurrente de la comunidad es que una skill de diseño por sí sola no arregla el resultado genérico. Lo que funciona es un sistema de diseño estricto y concreto más una revisión visual iterativa [H] ([r/ClaudeAI](https://reddit.sentinel-team.org/posts/1r0ie1y/snapshots/2026-02-10T08%3A25%3A54.387219Z)). La propia Anthropic admite que, incluso con prohibiciones explícitas, el modelo recurre a otras opciones comunes, como Space Grotesk [H] ([Anthropic](https://claude.com/resources/articles/improving-frontend-design-through-skills)). La estrategia es **anclarse a un sistema existente y probado**, no inventar una estética "distintiva" [D].

**Elección [D]:**

1. **Componentes:** shadcn/ui (Radix + Tailwind) con su **skill oficial**. La skill lee el proyecto con `shadcn info --json`, cubre el theming de **Tailwind v3 y v4** y se activa cuando existe `components.json` [H] ([shadcn Skills](https://ui.shadcn.com/docs/skills)). La web de shadcn migró a v4 en mayo de 2025, así que los ejemplos nuevos asumen v4, pero el theming de v3 sigue documentado [H] ([shadcn changelog](https://ui.shadcn.com/docs/changelog/2025-05-new-site)). Gráficas con shadcn charts (Recharts). La compatibilidad de la versión de Recharts con React 19 **no está verificada** y hay que comprobarla en F7.
2. **Tokens:** un `DESIGN.md` de un producto real, sacado de VoltAgent/awesome-design-md (MIT). Cada archivo trae 9 secciones (tema, roles de color, tipografía, componentes, layout, elevación, do's/don'ts, responsive y guía para el agente) con previews claro y oscuro. Entre los ejemplos están **Sentry** ("dark, data-dense dashboard"), **Linear** y **Vercel** [H] ([awesome-design-md](https://github.com/VoltAgent/awesome-design-md)). Recomiendo **Sentry** como base, porque es una herramienta de desarrolladores densa en datos y con severidades, con el acento neutralizado. Linear queda como alternativa. Los tokens se mapean a variables CSS de shadcn en `tailwind.config.js` (v3), en `web/src/styles/tokens.css`.
3. **Revisión:** Vercel **web-design-guidelines**, con más de 100 reglas de accesibilidad, foco, formularios, movimiento reducido, modo oscuro, estados de carga, vacío y error, y virtualización (MIT) [H] ([vercel-labs/agent-skills](https://github.com/vercel-labs/agent-skills)). Las reglas de estilo de texto propias de Vercel (Title Case) se ignoran, porque la UI es en español.
4. **Lista de "señales de IA":** se toma de la versión actual de `frontend-design` (anthropics/skills) solo como lista de cosas a evitar, no por su empuje a estéticas originales [H] ([SKILL.md](https://raw.githubusercontent.com/anthropics/skills/main/skills/frontend-design/SKILL.md)).
5. **impeccable:** es opcional y está pendiente de decisión (sección 7). Su comando `document` captura el sistema visual **existente** en un DESIGN.md, y `npx impeccable detect` aplica 62 reglas deterministas (abuso de Inter, degradados morado-azul, tarjetas anidadas) [H] ([pbakaus/impeccable](https://github.com/pbakaus/impeccable)). Pero descarga un binario a `~/.impeccable/bin/`, instala hooks que se ejecutan fuera de la aprobación del modelo, envía telemetría anónima, y su modo live puede lanzar `claude`/`codex` con las comprobaciones de permisos desactivadas [H] ([pbakaus/impeccable](https://github.com/pbakaus/impeccable)).
6. **Descartados como guía principal:** ui-ux-pro-max (genera sistemas nuevos a partir de datos; la revisión automática de Tessl lo puntuó entre 48% y 56%, con un SKILL.md de 659 líneas [H] ([Tessl](https://tessl.io/registry/skills/github/nextlevelbuilder/ui-ux-pro-max-skill/ui-ux-pro-max/review))) y Tremor Blocks (fuentes comunitarias dicen que requiere Tailwind v4, sin confirmación oficial [H] ([skills.sh](https://skills.sh/dodatech/approved-skills/tremor-design-system))). Tremor sirve solo como referencia de patrones.

**Instalación segura [D].** Copiar el texto de `SKILL.md`, `DESIGN.md` y `AGENTS.md` a `.claude/skills/` o al repo, sin instaladores `npx`. Las skills que son solo Markdown son de bajo riesgo [H] ([notas de skills](https://github.com/VoltAgent/awesome-design-md)). Cada instalación requiere la aprobación del usuario.

**Patrones prohibidos en `web/DESIGN.md` [D, con fuentes H donde se indica]:**

- Degradados en fondos, botones o números. También "hero de número grande con degradado" [H frontend-design].
- El "kit de tarjetas SaaS": rejilla de tarjetas idénticas redondeadas con sombra suave [H frontend-design]. Tampoco tarjetas anidadas [H impeccable].
- Tarjetas con borde izquierdo de color como único indicador de estado [H, queja en r/ClaudeAI].
- Etiquetas "eyebrow" en mayúsculas con tracking amplio, marcadores 01/02/03 y una palabra del titular resaltada en color [H frontend-design].
- La paleta crema/terracota (#F4F1EA / #D97757) y "casi negro con un acento ácido" [H frontend-design]. Tampoco degradados morado-azul [H impeccable].
- Inter y Space Grotesk como "elección por defecto" sin justificar [H Anthropic]. Se usa la tipografía que defina el DESIGN.md de referencia, o la del sistema operativo.
- Glassmorphism, emojis en títulos y hero centrado en pantallas de aplicación.
- Animaciones de hover y fade dispersas [H frontend-design]. Solo transiciones funcionales de ≤ 150 ms, desactivadas con `prefers-reduced-motion`.
- CSS en línea y overrides sueltos [H, queja en r/ClaudeAI]. Todo color, espacio y radio sale de los tokens.

**Reglas positivas [D]:**

- Tablas densas con cabecera fija y virtualización a partir de 200 filas.
- Monoespaciada **solo** para código, rutas e IDs de regla.
- Paleta de severidad (critical, high, medium, low, info) con contraste AA verificado y siempre acompañada de texto o icono, nunca solo color.
- Estados de carga, vacío y error en cada vista, incluido "despertando el servidor" si el hosting tiene arranque en frío.
- Atajos de teclado (`j`/`k` para navegar hallazgos, `/` para buscar) y paleta de comandos de shadcn.

**Pantallas (RF-23) [D]:**

| Pantalla | Contenido |
|---|---|
| Inicio de sesión | Botón de Google y nada más. Sin hero de marketing. |
| Proyectos | Tabla: nombre, último escaneo, abiertos por severidad (barra apilada fina) y fecha. |
| Proyecto · resumen | Gráfica de abiertos por severidad en el tiempo, nuevos frente a corregidos por escaneo, MTTR mediano y lista de escaneos. |
| Nuevo escaneo | Pestañas: pegar código (CodeMirror, ya presente [C]), subir ZIP (con los límites visibles) o repo de GitHub. Selector de reglas. |
| Escaneo en curso | Estado, progreso de archivos y botón de cancelar. Polling. |
| Resultados del escaneo | Tabla de hallazgos con filtros (severidad, regla, cambio, triage, ruta) y un panel lateral con el código resaltado, la traza taint paso a paso y el panel didáctico (RF-24). |
| Diff entre escaneos | Tres columnas plegables: nuevos, corregidos y reabiertos. |
| Issue | Ubicación actual, ocurrencias por escaneo, triage con justificación e historial de eventos y comentarios. |
| Catálogo de reglas | Lista por lenguaje y motor, con insignia "heurística" en las regex. Cada regla con su explicación, ejemplos vulnerable y corregido, CWE y OWASP. |
| Ajustes y Acerca de | Sesión, borrado de datos, límites y la propuesta de valor con afirmaciones honestas. |

**Herramientas de revisión por pantalla [D]:**

1. Revisión contra Vercel web-design-guidelines.
2. Auditoría WCAG 2.1 AA (skill `design:accessibility-review`, ya disponible en esta sesión).
3. Crítica estructurada (`design:design-critique`) sobre capturas reales.
4. Bucle de capturas con Playwright, la técnica que describe un usuario en r/ClaudeAI [H] ([r/ClaudeAI](https://reddit.sentinel-team.org/posts/1r0ie1y/snapshots/2026-02-10T08%3A25%3A54.387219Z)).
5. Opcionalmente, `impeccable detect` en CI si se aprueba.

---

## 5. Plan por fases con herramientas y criterio de terminado

Las versiones marcadas como **"a fijar"** no se verificaron en la investigación. Se fijan en el lock al instalar, con la aprobación del usuario. Las que sí tienen fuente: Flask-SQLAlchemy **3.1.x** sobre SQLAlchemy **2.0** [H] ([Flask-SQLAlchemy](https://flask-sqlalchemy.readthedocs.io/en/stable/quickstart/)), Flask-Limiter **4.1.1** [H] ([Flask-Limiter](https://flask-limiter.readthedocs.io/en/stable/)), Procrastinate (Python ≥ 3.10, PostgreSQL ≥ 13) [H] ([Procrastinate](https://procrastinate.readthedocs.io/en/stable/)). Se mantienen las versiones del front actual: React 19, TS, Vite 8, Tailwind 3, zustand y CodeMirror [C].

### F0 · Línea base, documentación y corpus anotado (1 semana)

- **Objetivo:** congelar el comportamiento actual y hacer medibles los defectos antes de tocar nada.
- **Archivos:**
  - Unificar dependencias en `pyproject.toml` y un lock, y borrar `api/requirements.txt` cuando el lock lo sustituya.
  - Corregir el README: versión única, `samples/` y puerto.
  - Crear `tests/rules/cases/` con los 12 casos actuales más los de esta sesión como `todoruleid` / `todook`.
  - Crear `tests/golden/` con el JSON y el SARIF actuales de `samples/`.
- **Herramientas:** pytest (actual), coverage y pip-tools o uv para el lock (a fijar).
- **Terminado:** los 38 tests actuales pasan, existe el arnés de anotaciones y hay un informe de línea base con hallazgos, tiempos por KLOC y los 5 defectos reproducidos.
- **Riesgos:** que el corpus sea demasiado pequeño. Mitigación: al menos 1 verdadero positivo y 1 verdadero negativo por regla, más los ejercicios de PyGoat como corpus externo (pendiente de verificar su licencia).

### F1 · Motor de reglas con contrato (2 semanas)

- **Objetivo:** observación 2.
- **Archivos:**
  - Nuevos: `sast/rules/api.py`, `sast/rules/registry.py`, `sast/engine/context.py` (`FileContext`), `sast/engine/runner.py`, `sast/engine/dedupe.py`, `sast/engine/suppress.py`, `sast/rules/yaml_loader.py` + `schema.py` (pydantic), `sast/rules/builtin/*.py` (12 reglas migradas), `sast/rules/yaml/` (las reglas de tipo lista negra, de patrón simple y regex de otros lenguajes pasan a YAML), `docs/rules/<id>.md` (explicación en español).
  - `core/dataflow.py` se integra en `FileContext.taint` como una sola pasada.
  - `rules/engine.py` queda como fachada temporal sobre el runner y se elimina `DEFAULT_RULES`.
  - Reportes: añadir `toolExecutionNotifications`, `partialFingerprints` y `variant`.
- **Herramientas:** pydantic v2 (a fijar), `importlib.metadata` (stdlib) y `functools.cached_property` (stdlib).
- **Terminado:**
  - MD5 da 1 hallazgo.
  - El MD5 con `usedforsecurity=False` da 0.
  - Una regla que lanza una excepción aparece en `rule_errors`.
  - Un test de carga falla ante IDs duplicados o sin caso de test.
  - Tiempo por KLOC ≤ 1/3 del de la línea base (objetivo).
  - Los golden de F0 solo cambian donde se corrigió un defecto, y cada diferencia está justificada.
- **Riesgos:**
  - El subconjunto YAML puede crecer sin control. Se limita a `call`, `call-either`, `not`, `inside`, `metavar-regex` y `regex`.
  - Hay que conservar la paridad con la CLI.

### F2 · Taint inter-procedural en archivo y secretos en argumentos (1–2 semanas)

- **Objetivo:** RF-09 y RF-10, y la credibilidad técnica del auto-escaneo.
- **Archivos:** `sast/taint/models.yaml`, `sast/taint/summaries.py` (`Summary`, orden topológico inverso, punto fijo acotado), `sast/taint/callgraph.py`, la regla `py/hardcoded-secret` ampliada (valor por defecto de `getenv`/`environ.get` y literales de alta entropía o con nombre sensible como argumento), y `supersedes` de `py/command-injection` sobre `py/dangerous-function`.
- **Herramientas:** solo stdlib (`ast`).
- **Terminado:** `request.args → helper(v) → os.system` da `py/command-injection` con traza de 3 pasos, y el auto-escaneo de la `api/` **actual** encuentra el secreto de respaldo y las contraseñas demo.
- **Riesgos:**
  - Falsos positivos por la regla conservadora de "callee desconocido". Se mitiga con confianza MEDIUM y casos `todook`.
  - Atributos `self.x` no modelados (hueco conocido de la investigación).

### F3 · App factory, configuración y PostgreSQL (2 semanas)

- **Objetivo:** observación 4 y la base de la 3.
- **Archivos:**
  - `api/__init__.py:create_app(settings)`: extensiones `db`, `migrate` y `limiter`; blueprints `/api/v1`; manejadores de error; logging.
  - `api/settings.py` (`pydantic-settings`, sin valores de respaldo).
  - `api/models/` (las tablas de la sección 4.3).
  - `migrations/` (Alembic).
  - `api/services/fingerprint.py`, `api/services/matcher.py`, `api/services/issue_service.py`, `api/services/metrics_service.py`.
  - `api/views/schemas.py` (serializadores con campos en lista blanca).
  - Se elimina el `_engine` global de `rules_service`.
- **Herramientas:** Flask-SQLAlchemy 3.1.x, SQLAlchemy 2.0, Flask-Migrate/Alembic (a fijar), psycopg 3 (a fijar), pydantic-settings (a fijar) y PostgreSQL 16 en compose (a fijar; ≥ 13 si se usa Procrastinate).
- **Terminado:**
  - El arranque falla sin `SECRET_KEY`.
  - `flask db upgrade` y `downgrade` funcionan en CI contra un Postgres real.
  - Test de emparejador: mover el código 20 líneas no crea issues nuevos, borrar la línea pasa el issue a `fixed`, restaurarla lo pasa a `reopened`, y un FP sigue siendo FP.
  - El diff coincide con `baselineState`.
- **Riesgos:**
  - Un fingerprint mal normalizado duplica issues. Se mitiga con `fingerprint_version` y tests de propiedades.
  - Los enums nativos de PostgreSQL son difíciles de alterar, por eso se usa VARCHAR + CHECK.

### F4 · Worker asíncrono, contenedor y endurecimiento de entradas (2 semanas)

- **Objetivo:** observación 3, parte de infraestructura.
- **Archivos:**
  - `api/worker/__main__.py` (bucle `SKIP LOCKED`, heartbeat, reaper, `ProcessPoolExecutor(max_tasks_per_child=1)` con timeout, cancelación cooperativa).
  - `api/services/archive.py`, que sustituye a `file_service` con los límites de ZIP de RNF-01 sin extraer a disco.
  - `api/services/github_service.py` (RNF-01).
  - `Dockerfile` multi-stage, `.dockerignore`, `docker/entrypoint.sh`, `gunicorn.conf.py`.
  - `docker-compose.yml` con los servicios `db` (healthcheck `pg_isready`), `migrate` (de un solo uso), `api` y `worker`, todos con la misma imagen y distinto comando, y `depends_on` con `service_healthy` / `service_completed_successfully`.
  - Se eliminan `vercel.json` y `server.py` del backend.
- **Herramientas:** Docker / Compose v2 (instalación local con aprobación), Gunicorn (a fijar) e imagen `python:3.12-slim`.
- **Alternativa:** Procrastinate en lugar de la tabla propia, si se prefiere una librería con reintentos y abort [H] ([Procrastinate cancel](https://procrastinate.readthedocs.io/en/stable/howto/advanced/cancellation.html)). RQ o Celery exigen Redis; Celery no se justifica aquí [D].
- **Terminado:**
  - `docker compose up` levanta todo con un solo comando.
  - Una bomba ZIP (42.zip o una generada), una entrada `../../x`, un symlink y un ZIP con 20.000 entradas se rechazan con 413/422 sin agotar memoria.
  - Un escaneo que pasa del timeout termina como `failed:timeout`.
  - Matar el worker a mitad de un escaneo lo devuelve a `queued`.
  - `/readyz` está en verde.
- **Riesgos:**
  - En Render free no hay workers de fondo: el worker tendría que correr dentro del contenedor web, y el apagado tras 15 min corta trabajos [H] ([Render Free](https://render.com/docs/free)).
  - Con tráfico web y worker en el mismo contenedor de 512 MB puede haber presión de memoria.

### F5 · Seguridad de la API: BFF, OIDC, CSRF, cabeceras, límites y auditoría (2 semanas)

- **Objetivo:** la parte de sesión, autenticación, CSRF, cabeceras, límites y auditoría de RNF-01.
- **Archivos:**
  - `api/services/auth_service.py` reescrito: Authlib, PKCE + state + nonce que fallan cerrados, y sesiones en base de datos.
  - Se eliminan JWT HS256, el secreto de respaldo y los usuarios demo.
  - `api/middleware/session.py`, `csrf.py`, `security_headers.py`, `request_id.py` y `api/services/audit.py`.
  - `ProxyFix(x_for=1)` detrás del PaaS.
  - Límites de Flask-Limiter en `/auth/*`, más cuotas de escaneo por base de datos.
  - Tests BOLA parametrizados sobre todos los endpoints.
- **Herramientas:** Authlib (a fijar), Flask-Limiter 4.1.1 y flask-talisman o un `after_request` propio (a fijar).
- **Almacenamiento del limitador:** `memory://` es solo para pruebas; en producción Flask-Limiter necesita Redis/Valkey, Memcached o MongoDB [H] ([Flask-Limiter](https://flask-limiter.readthedocs.io/en/stable/)). Ver la decisión D4.
- **Terminado:**
  - Ningún token en la URL ni en `localStorage`.
  - Callback sin state o con state distinto → 400.
  - POST sin `X-CSRF-Token` o con `Origin` ajeno → 403.
  - Usuario B → 404 en los recursos de A.
  - Errores sin texto interno.
  - Eventos de auditoría presentes.
  - Checklist ASVS L2 de la sección 3.2 firmado ítem por ítem.
- **Riesgos:** la cookie `__Host-` exige que la SPA y la API compartan origen (decisión D2). `SameSite=Strict` no viaja en la redirección cross-site desde Google; por eso la cookie de login temporal es `Lax` [D, con base en H ([IETF BCP](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/))].

### F6 · API v1 completa y retirada de rutas antiguas (1 semana)

- **Objetivo:** cerrar el contrato de la sección 4.1.
- **Archivos:**
  - `api/controllers/{projects,scans,issues,rules,metrics,auth,health}.py`.
  - `api/views/` (serializadores y renderizadores de informes SARIF, JSON y HTML a partir de la base de datos).
  - `docs/api/openapi.yaml`.
  - Alias `308` para `/api/*` durante una versión, y se elimina el registro doble de rutas.
- **Herramientas:** spectral u openapi-spec-validator para validar el contrato (a fijar, opcional).
- **Terminado:** tests de contrato para cada fila de la tabla 4.1, y el SARIF del endpoint validado contra el esquema 2.1.0.
- **Riesgos:** romper el front actual antes de F7. Se mitiga con los alias.

### F7 · Interfaz web anclada a un sistema probado (2–3 semanas)

- **Objetivo:** RF-23, RF-24 y RNF-05.
- **Archivos:**
  - `web/DESIGN.md` (derivado del DESIGN.md de Sentry o Linear, con las prohibiciones de la sección 4.4).
  - `web/components.json` y `web/src/components/ui/` (shadcn), `web/src/styles/tokens.css`, `tailwind.config.js` (variables v3).
  - Páginas: `Projects`, `ProjectOverview`, `NewScan`, `ScanRun`, `ScanResults`, `ScanDiff`, `Issue`, `Rules`, `Settings`, `About`, `Login`.
  - `web/src/api/client.ts` (fetch same-origin con `credentials:'include'` y `X-CSRF-Token`).
  - Se elimina `sast.history.v1` y el JWT de `localStorage`.
- **Herramientas:** skill oficial de shadcn y CLI de shadcn (a fijar), shadcn charts / Recharts (verificar compatibilidad con React 19), Vercel web-design-guidelines (copiando `AGENTS.md`), las skills `design:accessibility-review` y `design:design-critique`, y Playwright para capturas (a fijar). impeccable solo si se aprueba D5.
- **Terminado:**
  - Cada pantalla pasa la revisión de Vercel guidelines y la auditoría AA, sin ninguno de los patrones prohibidos (lista de comprobación manual + `detect` si se aprueba).
  - Estados de carga, vacío y error presentes.
  - Una prueba con 2–3 estudiantes reales (tarea: "corrige el hallazgo más grave usando el panel") que termina sin ayuda.
- **Riesgos:** volver a una "estética de IA" por muestreo del modelo. Se mitiga con revisiones deterministas y capturas, y no aceptando una pantalla sin compararla con el DESIGN.md.

### F8 · Valor demostrable, CI y despliegue (1–2 semanas)

- **Objetivo:** cerrar la observación 1 con datos.
- **Archivos:**
  - `sast/bench/` + `sast bench`.
  - `docs/benchmark.md`: precisión y recall por regla en el corpus anotado frente a Bandit y Semgrep CE/Opengrep sobre los mismos archivos.
  - `docs/valor.md`: la propuesta de la sección 2.
  - `.github/workflows/ci-quality.yml` ampliado: servicio Postgres, migraciones, tests, auto-escaneo, Bandit como control cruzado, build de la imagen y subida de SARIF con la acción oficial.
  - Despliegue según D1.
- **Herramientas:** Bandit (una fuente secundaria da la 1.9.3 de enero de 2026; sin verificar en PyPI [H] ([appsecsanta](https://www.appsecsanta.com/bandit))), Semgrep CE u Opengrep (LGPL 2.1) usados como competidores en el benchmark, no incrustados, y GitHub Actions (actual).
- **Terminado:** el README solo hace afirmaciones de la columna "se puede" de la sección 2.3, cada cifra enlaza a `docs/benchmark.md`, y la demo funciona en el hosting elegido con arranque en frío señalizado.
- **Riesgos:** que el benchmark salga desfavorable. Es aceptable y honesto: el valor no depende de ganar, y la literatura muestra que incluso las herramientas maduras tienen recall bajo [H] ([Li et al.](https://kaixuanli-ecnu.github.io/papers/java-sast-fse23.pdf)).

**Orden y dependencias [D].** F1 y F2 (motor) pueden avanzar en paralelo con F3 (base de datos), porque se tocan solo en `Finding` y el fingerprint. F4 depende de F3. F5 conviene hacerla inmediatamente después de F4 y **antes** de cualquier despliegue público. F7 puede empezar el DESIGN.md y los componentes durante F5–F6 con datos simulados. Duración total estimada: 14–18 semanas a tiempo parcial. Es una estimación propia, sin fuente.

---

## 6. El hosting decide la cookie, el worker y el coste

| Opción | Hechos [H] | Consecuencia para el diseño [D] |
|---|---|---|
| **Docker Compose local / laboratorio** | Gratis. | Es la demo principal y el entorno de evaluación. Todo el plan funciona sin cambios. |
| **Render free (web) + Neon free (Postgres)** | Render free se duerme a los 15 min y tarda ~1 min en despertar, no tiene workers de fondo gratis, no tiene disco persistente y no permite el pre-deploy en free. Su Postgres free caduca a los 30 días (+14 de gracia) ([Render Free](https://render.com/docs/free); [Render Deploys](https://render.com/docs/deploys)). Neon free: 1 GB por proyecto, scale-to-zero a los 5 min que no se puede desactivar, pooling de hasta 10.000 conexiones ([Neon](https://neon.com/pricing)). | El worker vive dentro del contenedor web, las migraciones van en el entrypoint con una sola instancia, el reaper es imprescindible y la UI muestra "despertando". Si se usa el host `-pooler` en modo transacción, conviene `NullPool` o un pool mínimo. |
| **Railway Hobby** | $5/mes con $5 de uso incluidos y hasta 6 réplicas. El plan Free da $1/mes de crédito y 0,5 GB de RAM ([Railway](https://docs.railway.com/reference/pricing/plans)). | La opción más limpia: servicios `api` y `worker` separados con la misma imagen, y Postgres en el mismo proyecto. No se verificó si incluye Redis gratis. |
| **VPS pequeño + compose** | Sin datos de precio en las notas. | Control total (Postgres, Redis para el limitador, mismo origen con un reverse proxy). Exige mantener parches y copias de seguridad. |
| **Fly.io + Neon** | Sin free tier para organizaciones nuevas. Máquina de 512 MB a $3,69/mes. Su Postgres gestionado empieza en $38/mes ([Fly.io](https://docs.fly.io/about/pricing)). | Barato por máquina, pero solo tiene sentido con Neon. |

La SPA puede seguir en Vercel como hosting estático, porque los límites de Vercel afectan a las Functions, no a los estáticos [D, con base en H ([Vercel Limits](https://vercel.com/docs/functions/limitations))]. Pero eso choca con la cookie `__Host-` si la API está en otro sitio (ver D2).

---

## 7. Decisiones abiertas para el usuario

**D1 · Hosting de la demo pública.** Las opciones son Render free + Neon (gratis, con arranque en frío y worker embebido), Railway Hobby ($5/mes, la arquitectura limpia), un VPS con compose (control total y más mantenimiento) o solo local. *Recomendación [D]:* compose local como entrega principal y Railway Hobby si se necesita una URL pública estable. Render + Neon si el presupuesto es estrictamente cero.

**D2 · Mismo sitio para las cookies.** El BCP de OAuth para apps de navegador (publicado como RFC 10017, agosto de 2026) prefiere despliegues en el mismo dominio y la cookie `__Host-` sin `Domain` [H] ([IETF datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/)). Si se mantiene `*.vercel.app` + `*.<paas>.app`, haría falta `SameSite=None`, y la sesión fallaría en navegadores que bloquean cookies de terceros. Chrome no las elimina, pero Incógnito las bloquea por defecto [H] ([Search Engine Land](https://searchengineland.com/google-third-party-cookies-chrome-reversal-444317)). Las opciones son:

- **(a)** Servir la SPA compilada desde el mismo contenedor o reverse proxy. Es lo más simple y no necesita CORS. *Recomendada [D].*
- **(b)** Reescritura `/api/*` en Vercel hacia el backend. La documentación de rewrites de Vercel **no se verificó**.
- **(c)** Dominio propio con `app.` y `api.` como subdominios. Requiere comprar un dominio, y la cookie dejaría de poder ser `__Host-` si se comparte entre subdominios.

**D3 · Cola propia (`SKIP LOCKED`) o Procrastinate.** La cola propia son unas 100 líneas, didácticas y sin dependencias. Procrastinate da reintentos y abort ya hechos, pero aplica su propio esquema [H] ([Procrastinate](https://procrastinate.readthedocs.io/en/stable/)). *Recomendación [D]:* cola propia, porque se presta mejor a mostrar la arquitectura en la evaluación.

**D4 · Redis/Valkey para el rate limiting.** Sin Redis, Flask-Limiter solo es fiable en desarrollo [H]. Las opciones son añadir un contenedor Valkey (trivial en compose o VPS; en Render free es efímero [H] ([Render Free](https://render.com/docs/free))) o limitar solo con cuotas en PostgreSQL más el limitador en memoria por worker (más débil). *Recomendación [D]:* Valkey en compose y VPS, y cuotas en base de datos como respaldo en todos los entornos.

**D5 · Adoptar impeccable.** A favor: `document`, `audit`, `critique` y un detector determinista de 62 reglas, con licencia Apache 2.0. En contra: descarga un binario, instala hooks fuera de la aprobación del modelo, envía telemetría (no se pudo confirmar si se puede desactivar) y tiene un modo live que lanza agentes sin comprobaciones de permisos [H] ([pbakaus/impeccable](https://github.com/pbakaus/impeccable)). No se encontró ninguna auditoría de seguridad independiente. Las opciones son: (a) no adoptarlo y usar la lista manual de patrones prohibidos más Vercel guidelines; (b) copiar solo el texto de la skill, sin binario, hooks ni live; (c) además ejecutar `npx impeccable detect` en un contenedor aislado sin red tras la descarga. *Recomendación [D]:* (b), y (c) solo si el usuario aprueba expresamente ejecutar el binario.

**D6 · DESIGN.md de referencia.** Sentry (oscuro y denso en datos) o Linear/Vercel (más neutros). *Recomendación [D]:* Sentry con acento neutralizado y modo claro derivado. No se verificó que los archivos de awesome-design-md coincidan con los sitios actuales [H] ([awesome-design-md](https://github.com/VoltAgent/awesome-design-md)).

**Decisiones menores:**

- Si se permite el escaneo anónimo de código pegado en la demo pública. *Recomendación [D]:* no, por las cuotas y la auditoría.
- La política de retención de ocurrencias: 90 días propuestos. ASVS no fija un plazo [H] ([ASVS V14](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x23-V14-Data-Protection.md)).
- Si se restringe el login a un dominio institucional con la validación `hd` de Google [H] ([Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect)).

---

## Conclusión

Lo que cambia con esta investigación es el criterio de éxito. La pregunta "¿qué lo diferencia?" no se responde con más reglas ni con un motor más potente, porque las capacidades que dan precisión son justo las que se pagan en el mercado. Se responde convirtiendo en entregables verificables lo que ningún competidor revisado combina: explicación didáctica en español por hallazgo, progreso medido entre escaneos con issues que sobreviven a los cambios de línea, despliegue propio sin enviar código a terceros y un catálogo de reglas pequeño con contrato y tests que un estudiante puede leer y ampliar. El benchmark de F8 cumple un papel defensivo: no está para ganar, sino para que el proyecto nunca afirme algo que no ha medido.

La segunda conclusión es que las cuatro observaciones del ingeniero tienen una causa común: faltan contratos explícitos. No había contrato entre el motor y las reglas, ni entre la API y su plataforma, ni entre el navegador y la sesión, ni entre un escaneo y el siguiente. Los artefactos centrales de esta especificación son los que fijan esos contratos: el protocolo `Rule`/`FileContext`, la tabla de endpoints `/api/v1`, la cookie `__Host-` con OIDC que falla cerrado, y el fingerprint `sastfp/v1` con `fingerprint_version`. Si se respetan, el resto del refactor es trabajo de implementación con criterios de terminado comprobables. Las dos decisiones que más condicionan el calendario son D1 y D2, y deberían tomarse antes de empezar F4.
