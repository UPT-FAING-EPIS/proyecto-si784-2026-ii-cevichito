# Reporte 2 · Pruebas de integración y de sistema

| | |
|---|---|
| **Proyecto** | SAST Studio |
| **Tipo de prueba** | Integración y sistema |
| **Herramientas** | pytest 9, pytest-html 4, PostgreSQL 16 (servicio de GitHub Actions), requests |
| **Automatización** | Job `2 · Integración y sistema` de `.github/workflows/pruebas.yml` |
| **Fecha del run** | 16 de noviembre de 2026 |
| **Resultado** | ✅ Integración: 180 de 180 pasan · Sistema: 7 de 7 pasan |

## 1. Objetivo

- **Integración:** comprobar que las piezas trabajan juntas (controladores, servicios, modelos,
  base de datos, worker y motor) usando la **base de datos real, PostgreSQL 16**, con las
  migraciones de Alembic aplicadas igual que en producción.
- **Sistema:** comprobar el **producto completo funcionando como en producción**: el servidor
  web y el worker como procesos separados, la cola real en la base de datos y peticiones HTTP
  de verdad, sin atajos internos.

## 2. Diferencia entre las dos

| | Integración (`tests/api`) | Sistema (`tests/e2e/test_sistema.py`) |
|---|---|---|
| Cómo se llama a la aplicación | Cliente de pruebas de Flask, en el mismo proceso | HTTP real contra un servidor en marcha |
| Worker | Se invoca directamente desde la prueba | Proceso aparte que reclama de la cola |
| Base de datos | PostgreSQL 16 con migraciones (en la CI) | SQLite con migraciones reales |
| Web compilada | No | Sí: también se comprueba que se entrega |
| Velocidad | Rápida, permite muchos casos | Más lenta, pocos recorridos completos |

El servidor de las pruebas de sistema lo arranca `scripts/servidor_pruebas.py`: aplica las
migraciones, lanza el worker y el servidor web, y espera a que `/readyz` responda.

## 3. Pruebas de integración

| Archivo | Pruebas | Qué verifica |
|---|---:|---|
| `test_worker.py` | 50 | Creación y validación de escaneos, cuotas, cancelación, worker de punta a punta (código pegado y ZIP), bombas ZIP, resultado parcial por tiempo, reaper, `SKIP LOCKED`, caché por contenido, orden de la cola y descarga de GitHub |
| `test_contract.py` | 42 | Cada ruta de la API: códigos de estado, formato de respuesta, paginación y que **todas** las rutas exigen sesión y propiedad (anti-BOLA) |
| `test_security.py` | 37 | Login OIDC con PKCE, `state` y `nonce`, cookie de sesión segura, expiración y cierre de sesión, CSRF y comprobación de origen, cabeceras de seguridad, errores genéricos y limitador del login |
| `test_challenges.py` | 26 | Catálogo de retos, que cada solución de referencia supera su reto, veredictos y que nunca se expone la solución |
| `test_persistence.py` | 20 | Configuración segura (secretos obligatorios, login de desarrollo prohibido en producción), ciclo de vida de los issues (nuevo, corregido, reabierto), falso positivo conservado entre escaneos, secretos enmascarados, comparación, métricas, borrado en cascada, `/readyz` y auditoría de solo añadir |
| `test_config.py` | 3 | Configuración pública (`/config`): límites y proveedor de acceso, sin exponer secretos |
| `test_openapi.py` | 2 | El contrato OpenAPI es válido y documenta todas las rutas |
| **Total** | **180** | |

## 4. Pruebas de sistema

| # | Prueba | Qué comprueba |
|---|---|---|
| 1 | `test_el_servicio_esta_vivo_y_con_migraciones` | `/healthz` responde y `/readyz` confirma la base de datos con las migraciones al día |
| 2 | `test_la_web_se_sirve_con_cabeceras_de_seguridad` | La web compilada se entrega con `Content-Security-Policy` y `X-Content-Type-Options` |
| 3 | `test_sin_sesion_la_api_responde_401` | Sin iniciar sesión, la API no responde datos |
| 4 | `test_flujo_completo_escanear_corregir_y_comparar` | Escanear código vulnerable → el worker detecta la inyección SQL → escanear la versión corregida → la comparación la marca como corregida |
| 5 | `test_informes_sarif_json_y_html` | Los tres informes se descargan; el SARIF es 2.1.0 válido y contiene el hallazgo |
| 6 | `test_un_usuario_no_ve_los_proyectos_de_otro` | Un segundo usuario recibe 404 al abrir el proyecto de otro y no lo ve en su lista |
| 7 | `test_reto_de_correccion_de_principio_a_fin` | Enviar el código del reto da «sigue»; enviar la solución da «superado» y la lista lo refleja |

## 5. Resultados

| Suite | Pruebas | Pasan | Fallan | Omitidas | Tiempo |
|---|---:|---:|---:|---:|---:|
| Integración (PostgreSQL 16) | 180 | 180 | 0 | 0 | 72,0 s |
| Sistema (servidor real) | 7 | 7 | 0 | 0 | 12,2 s |

En local, sin `TEST_DATABASE_URL`, la integración usa SQLite en memoria y omite 2 pruebas que
solo tienen sentido en PostgreSQL: el reparto de trabajos con `SKIP LOCKED` y la auditoría de
solo añadir (un disparador de la base de datos).

## 6. Incidencia encontrada durante la automatización

En el primer run, la prueba de sistema 2 falló con **404** al pedir la página principal: el job
no compilaba la web antes de arrancar el servidor. Se corrigió compilando la web (`npm run
build`) en ese job. La prueba cumplió su función: comprueba que el servidor entrega la web, y
sin ella no lo hacía.

## 7. Evidencias

En el artefacto `reportes-de-pruebas` del run:

- `2-integracion-sistema/integracion.html`
- `2-integracion-sistema/sistema.html`

## 8. Conclusiones

- La API funciona igual sobre PostgreSQL 16 que sobre SQLite, con las migraciones reales.
- El recorrido completo (escanear, corregir, comparar e informar) funciona con los procesos
  separados como en producción, incluida la cola entre la web y el worker.
- El aislamiento entre usuarios se comprueba en las dos capas: en cada ruta (integración) y
  de punta a punta (sistema).
