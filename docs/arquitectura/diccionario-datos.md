# Diccionario de datos

Generado desde los modelos de SQLAlchemy (`api/models/entities.py`).

## `audit_log`

Registro de auditoría de solo inserción (RNF-01).

| Columna | Tipo | Nulo | Clave | Por defecto | Descripción |
|---|---|---|---|---|---|
| `id` | bigint | no | PK |  | Identificador de la fila. |
| `at` | datetime | no |  |  |  |
| `event` | varchar(60) | no |  |  |  |
| `user_sub` | varchar(255) | sí |  |  |  |
| `ip` | varchar(64) | sí |  |  |  |
| `user_agent` | varchar(400) | sí |  |  |  |
| `request_id` | varchar(64) | sí |  |  |  |
| `target_type` | varchar(40) | sí |  |  |  |
| `target_id` | varchar(64) | sí |  |  |  |
| `outcome` | varchar(20) | no |  | `success` |  |
| `details` | json | no |  |  |  |

Índices: `ix_audit_log_at`, `ix_audit_log_user_at`

## `issue_events`

Historial de un issue: cambios de estado, de triage y comentarios.

| Columna | Tipo | Nulo | Clave | Por defecto | Descripción |
|---|---|---|---|---|---|
| `id` | bigint | no | PK |  | Identificador de la fila. |
| `issue_id` | char(32) | no | FK → `issues.id` |  | Referencia a `issues`. |
| `user_id` | char(32) | sí | FK → `users.id` |  | Referencia a `users`. |
| `kind` | varchar(10) | no |  |  |  |
| `from_state` | varchar(20) | sí |  |  |  |
| `to_state` | varchar(20) | sí |  |  |  |
| `comment` | text | sí |  |  |  |
| `scan_id` | char(32) | sí | FK → `scans.id` |  | Referencia a `scans`. |
| `created_at` | datetime | no |  |  | Fecha y hora (UTC): created. |

Índices: `ix_issue_events_issue_created`

## `issues`

Problema de seguridad que persiste entre escaneos de un proyecto (mismo fingerprint). Lleva el triage.

| Columna | Tipo | Nulo | Clave | Por defecto | Descripción |
|---|---|---|---|---|---|
| `id` | char(32) | no | PK |  | Identificador de la fila. |
| `project_id` | char(32) | no | FK → `projects.id` |  | Referencia a `projects`. |
| `rule_id` | varchar(120) | no | FK → `rules.id` |  | Referencia a `rules`. |
| `category` | varchar(80) | no |  | `default` |  |
| `fingerprint` | varchar(64) | no |  |  |  |
| `fingerprint_version` | smallint | no |  | `1` |  |
| `line_hash` | varchar(64) | no |  | `` |  |
| `snippet_hash` | varchar(64) | no |  | `` |  |
| `lifecycle` | varchar(10) | no |  | `open` |  |
| `triage` | varchar(16) | no |  | `untriaged` |  |
| `triage_justification` | text | sí |  |  |  |
| `severity` | smallint | no |  |  |  |
| `current_path` | varchar(500) | no |  |  |  |
| `current_line` | integer | no |  | `0` |  |
| `message` | text | no |  | `` |  |
| `first_seen_scan_id` | char(32) | sí | FK → `scans.id` |  | Referencia a `scans`. |
| `last_seen_scan_id` | char(32) | sí | FK → `scans.id` |  | Referencia a `scans`. |
| `first_seen_at` | datetime | no |  |  | Fecha y hora (UTC): first seen. |
| `fixed_at` | datetime | sí |  |  | Fecha y hora (UTC): fixed. |
| `reopened_count` | integer | no |  | `0` |  |
| `assignee_id` | char(32) | sí | FK → `users.id` |  | Referencia a `users`. |

Índices: `ix_issues_project_id`, `ix_issues_project_state`

## `occurrences`

Aparición de un issue en un escaneo concreto: archivo, líneas, fragmento y traza.

| Columna | Tipo | Nulo | Clave | Por defecto | Descripción |
|---|---|---|---|---|---|
| `id` | char(32) | no | PK |  | Identificador de la fila. |
| `scan_id` | char(32) | no | FK → `scans.id` |  | Referencia a `scans`. |
| `issue_id` | char(32) | no | FK → `issues.id` |  | Referencia a `issues`. |
| `path` | varchar(500) | no |  |  |  |
| `start_line` | integer | no |  |  |  |
| `end_line` | integer | no |  |  |  |
| `start_col` | integer | no |  | `0` |  |
| `end_col` | integer | no |  | `0` |  |
| `message` | text | no |  |  |  |
| `severity` | smallint | no |  |  |  |
| `confidence` | smallint | no |  |  |  |
| `snippet` | text | no |  | `` |  |
| `line_hash` | varchar(64) | no |  | `` |  |
| `trace` | json | no |  |  |  |
| `variant` | varchar(200) | sí |  |  |  |
| `suppressed` | boolean | no |  | `False` |  |
| `suppression_reason` | varchar(500) | sí |  |  |  |
| `change` | varchar(10) | no |  | `new` |  |

Índices: `ix_occurrences_issue_id`, `ix_occurrences_scan_id`

## `projects`

Proyecto de un usuario: agrupa sus escaneos e issues. Los intentos de retos son proyectos ocultos.

| Columna | Tipo | Nulo | Clave | Por defecto | Descripción |
|---|---|---|---|---|---|
| `id` | char(32) | no | PK |  | Identificador de la fila. |
| `owner_id` | char(32) | no | FK → `users.id` |  | Referencia a `users`. |
| `name` | varchar(120) | no |  |  |  |
| `created_at` | datetime | no |  |  | Fecha y hora (UTC): created. |
| `challenge_id` | varchar(80) | sí |  |  |  |
| `challenge_solved_at` | datetime | sí |  |  | Fecha y hora (UTC): challenge solved. |

Índices: `ix_projects_challenge_id`, `ix_projects_owner_id`

## `rules`

Copia del catálogo del motor, sincronizada al arrancar (para FK y métricas).

| Columna | Tipo | Nulo | Clave | Por defecto | Descripción |
|---|---|---|---|---|---|
| `id` | varchar(120) | no | PK |  | Identificador de la fila. |
| `tool` | varchar(40) | no |  | `sast-studio` |  |
| `name` | varchar(200) | no |  |  |  |
| `default_severity` | smallint | no |  |  |  |
| `confidence` | smallint | no |  |  |  |
| `cwe` | json | no |  |  |  |
| `owasp` | json | no |  |  |  |
| `kind` | varchar(20) | no |  |  |  |
| `engine` | varchar(20) | no |  |  |  |
| `previous_ids` | json | no |  |  |  |
| `meta` | json | no |  |  |  |
| `version` | varchar(20) | no |  |  |  |

## `scan_result_cache`

Resultado del motor para un contenido concreto, para no analizarlo dos veces. La clave es un hash del contenido analizado, la versión del motor y las reglas pedidas: solo coincide quien tiene exactamente el mismo código, así que reutilizarlo no expone nada. Se guardan los hallazgos y el código solo de los archivos con hallazgos (comprimido).

| Columna | Tipo | Nulo | Clave | Por defecto | Descripción |
|---|---|---|---|---|---|
| `key` | varchar(64) | no | PK |  | Identificador de la fila. |
| `payload` | blob | no |  |  |  |
| `created_at` | datetime | no |  |  | Fecha y hora (UTC): created. |
| `hits` | integer | no |  | `0` |  |

Índices: `ix_scan_result_cache_created_at`

## `scan_uploads`

Contenido subido, guardado solo mientras el escaneo está pendiente (RNF-01).

| Columna | Tipo | Nulo | Clave | Por defecto | Descripción |
|---|---|---|---|---|---|
| `scan_id` | char(32) | no | PK, FK → `scans.id` |  | Identificador de la fila. |
| `content` | blob | no |  |  |  |
| `filename` | varchar(255) | no |  | `` |  |
| `sha256` | varchar(64) | no |  |  |  |
| `size` | integer | no |  |  |  |
| `created_at` | datetime | no |  |  | Fecha y hora (UTC): created. |

## `scans`

Un análisis de código: su origen, su estado en la cola, su progreso y el resumen de resultados.

| Columna | Tipo | Nulo | Clave | Por defecto | Descripción |
|---|---|---|---|---|---|
| `id` | char(32) | no | PK |  | Identificador de la fila. |
| `project_id` | char(32) | no | FK → `projects.id` |  | Referencia a `projects`. |
| `created_by` | char(32) | sí | FK → `users.id` |  | Referencia a `users`. |
| `source` | varchar(10) | no |  |  |  |
| `source_ref` | varchar(300) | no |  | `` |  |
| `category` | varchar(80) | no |  | `default` |  |
| `commit_sha` | varchar(64) | sí |  |  |  |
| `status` | varchar(10) | no |  | `queued` |  |
| `progress_done` | integer | no |  | `0` |  |
| `progress_total` | integer | no |  | `0` |  |
| `attempts` | integer | no |  | `0` |  |
| `cancel_requested` | boolean | no |  | `False` |  |
| `heartbeat_at` | datetime | sí |  |  | Fecha y hora (UTC): heartbeat. |
| `worker_id` | varchar(80) | sí |  |  |  |
| `queued_at` | datetime | no |  |  | Fecha y hora (UTC): queued. |
| `started_at` | datetime | sí |  |  | Fecha y hora (UTC): started. |
| `finished_at` | datetime | sí |  |  | Fecha y hora (UTC): finished. |
| `error_code` | varchar(40) | sí |  |  |  |
| `rules_enabled` | json | no |  |  |  |
| `rules_requested` | json | sí |  |  |  |
| `engine_version` | varchar(20) | sí |  |  |  |
| `loc_total` | integer | no |  | `0` |  |
| `files_scanned` | integer | no |  | `0` |  |
| `summary` | json | no |  |  |  |
| `rule_errors` | json | no |  |  |  |
| `baseline_scan_id` | char(32) | sí | FK → `scans.id` |  | Referencia a `scans`. |
| `request_id` | varchar(64) | sí |  |  |  |
| `partial` | boolean | no |  | `False` |  |
| `result_reused` | boolean | no |  | `False` |  |

Índices: `ix_scans_project_id`, `ix_scans_queue`, `ix_scans_stream`

## `sessions`

Sesión iniciada en el servidor. El navegador solo guarda el token; aquí se guarda su hash.

| Columna | Tipo | Nulo | Clave | Por defecto | Descripción |
|---|---|---|---|---|---|
| `id` | char(32) | no | PK |  | Identificador de la fila. |
| `user_id` | char(32) | no | FK → `users.id` |  | Referencia a `users`. |
| `token_hash` | varchar(64) | no | único |  |  |
| `csrf_secret` | varchar(64) | no |  |  |  |
| `created_at` | datetime | no |  |  | Fecha y hora (UTC): created. |
| `last_seen_at` | datetime | no |  |  | Fecha y hora (UTC): last seen. |
| `expires_at` | datetime | no |  |  | Fecha y hora (UTC): expires. |
| `revoked_at` | datetime | sí |  |  | Fecha y hora (UTC): revoked. |
| `ip` | varchar(64) | sí |  |  |  |
| `user_agent` | varchar(400) | sí |  |  |  |

Índices: `ix_sessions_expires_at`, `ix_sessions_user_id`

## `users`

Persona que entra con Google (o con el acceso de desarrollo). Se identifica por `google_sub`, no por el email.

| Columna | Tipo | Nulo | Clave | Por defecto | Descripción |
|---|---|---|---|---|---|
| `id` | char(32) | no | PK |  | Identificador de la fila. |
| `google_sub` | varchar(255) | no | único |  |  |
| `email` | varchar(320) | no |  |  |  |
| `name` | varchar(200) | no |  | `` |  |
| `created_at` | datetime | no |  |  | Fecha y hora (UTC): created. |
| `disabled_at` | datetime | sí |  |  | Fecha y hora (UTC): disabled. |
