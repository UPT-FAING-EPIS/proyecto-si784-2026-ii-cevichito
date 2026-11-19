# FD01 · Informe de Factibilidad

> Versión en Markdown del documento `FD01-EPIS-Informe de Factibilidad.docx` (el Word es la versión oficial, con portada, índice e imágenes).

![Imagen 1](media/md/fd01-imagen-1.png)

**UNIVERSIDAD PRIVADA DE TACNA**

**FACULTAD DE INGENIERÍA**

**Escuela Profesional de Ingeniería de Sistemas**

**SAST Studio: Analizador Estático de Seguridad Didáctico y Autoalojado**

Curso: CALIDAD Y PRUEBAS DE SOFTWARE (SI-784)

Docente: Mg. Ing. Patrick José Cuadros Quiroga

Integrante:

**Serrano Ibañez, Nestor Juice Yomar** **2022075747**

**Tacna – Perú**

**2026**

## SAST Studio: Analizador Estático de Seguridad Didáctico y Autoalojado

## Documento Informe de Factibilidad

## Versión 1.0

| CONTROL DE VERSIONES |  |  |  |  |  |
|---|---|---|---|---|---|
| Versión | Hecha por | Revisada por | Aprobada por | Fecha | Motivo |
| 1.0 | SINJ |  |  | 14/11/2026 | Versión original |

**Índice**

- SAST Studio: Analizador Estático de Seguridad Didáctico y Autoalojado
- Documento Informe de Factibilidad
- Versión 1.0
- Descripción del Proyecto
  - Nombre del proyecto
  - Duración del proyecto
  - Descripción
  - 1.4 Objetivos
- Riesgos
- Análisis de la Situación actual
  - Planteamiento del problema
  - Consideraciones de hardware y software
- Estudio de Factibilidad
  - Factibilidad Técnica
  - Factibilidad Económica
  - Factibilidad Operativa
  - Factibilidad Legal
  - Factibilidad Social
  - Factibilidad Ambiental
- Conclusiones

**Informe de Factibilidad**

## Descripción del Proyecto

### Nombre del proyecto

SAST Studio: Analizador Estático de Seguridad Didáctico y Autoalojado

### Duración del proyecto

*Tabla 1: Fases de desarrollo del proyecto*

| Fase | Fechas |
|---|---|
| F0 Línea base, dependencias y corpus anotado; visión y factibilidad | 04 sep – 18 sep 2026 |
| F1–F2 Motor de reglas con contrato y análisis de taint entre funciones | 19 sep – 09 oct 2026 |
| F3 App factory, configuración 12-factor y PostgreSQL | 10 oct – 17 oct 2026 |
| F4–F5 Worker de análisis, Docker y seguridad (OIDC, CSRF, límites) | 18 oct – 31 oct 2026 |
| F6–F7 API v1 completa e interfaz web nueva | 01 nov – 21 nov 2026 |
| F8 Benchmark, CI, análisis estático externo y despliegue en Render + Neon | 22 nov – 02 dic 2026 |
| Consolidación documental y entrega final | 03 dic – 04 dic 2026 |

Fuente Elaboración Propia

Nota. El cronograma contempla una duración total de 13 semanas lectivas del semestre 2026-II (aproximadamente 3 meses de trabajo continuo) y parte de la versión 0.1 del proyecto, que se refactoriza por fases.

### Descripción

En los cursos de programación y de seguridad de la Escuela Profesional de Ingeniería de Sistemas, los estudiantes rara vez revisan la seguridad de su propio código. Cuando lo hacen, recurren a la revisión manual o a herramientas de análisis estático pensadas para equipos de seguridad profesionales (Bandit, Semgrep, CodeQL), que muestran mensajes cortos en inglés, no explican por qué un fallo es peligroso ni cómo corregirlo y, en muchos casos, exigen subir el código a servicios de terceros.

El proyecto consiste en refactorizar y completar SAST Studio, una aplicación web y de línea de comandos que analiza estáticamente código fuente en busca de vulnerabilidades de seguridad clasificadas según OWASP Top 10 y CWE. Su diferencia frente a las herramientas existentes no es detectar más, sino enseñar: cada hallazgo se explica de forma didáctica (qué ocurre, por qué es peligroso, cómo corregirlo, ejemplo vulnerable y corregido, CWE/OWASP y recorrido del dato), y la aplicación mide el progreso entre escaneos (hallazgos nuevos, persistentes, corregidos y reabiertos), conservando la clasificación (triage) de cada hallazgo.

La solución es autoalojada (Docker y PostgreSQL), de modo que el código de los estudiantes no sale del servidor donde se instala. Se publica en https://sast-studio.onrender.com sobre servicios en la nube de plan gratuito (Render y Neon) y puede instalarse sin costo en un servidor de la universidad. Su público son estudiantes y docentes de cursos de programación y seguridad, y desarrolladores que aprenden seguridad. La versión 0.1 de partida era frágil (despliegue serverless con límites de 4,5 MB y 300 s, sesión JWT en localStorage, CORS abierto, secretos con valor por defecto, historial solo en el navegador); la versión 0.2 la reemplaza por una arquitectura MVC con worker, cola en base de datos y controles de seguridad alineados con OWASP ASVS 5.0 nivel 2.

### 1.4 Objetivos

#### 1.4.1 Objetivo general

Desarrollar una herramienta de análisis estático de seguridad didáctica y autoalojada, SAST Studio, que detecte vulnerabilidades OWASP Top 10 / CWE en código fuente, las explique de forma didáctica con ejemplos de corrección y mida el progreso de los estudiantes entre escaneos, desplegada sin costo de infraestructura para su uso en los cursos de la Escuela Profesional de Ingeniería de Sistemas de la Universidad Privada de Tacna.

#### 1.4.2 Objetivos Específicos

- Construir un motor de reglas con contrato: 22 reglas (13 de Python con análisis de árbol sintáctico y de taint entre funciones del mismo archivo, 8 heurísticas multilenguaje y 1 de secretos), cada una con casos de prueba anotados y huella estable sastfp/v1 para identificar el hallazgo aunque el código cambie de línea.
- Explicar cada hallazgo de forma didáctica: qué ocurre, por qué es peligroso, cómo corregirlo, ejemplo vulnerable y corregido, CWE, categoría OWASP y recorrido del dato desde la fuente hasta el punto peligroso.
- Permitir escanear código pegado, archivos ZIP y repositorios públicos de GitHub mediante una cola de trabajos en PostgreSQL procesada por un worker en segundo plano, con prioridad, turnos por usuario, tiempo límite, recuperación de trabajos interrumpidos y caché de resultados.
- Dar seguimiento a los hallazgos entre escaneos: comparación con el escaneo anterior, clasificación (triage) con justificación, comentarios, historial y métricas (abiertos por severidad, nuevos frente a corregidos, tiempo mediano de corrección y densidad por cada 1000 líneas).
- Proteger la aplicación y el código analizado con inicio de sesión OIDC (Google), sesión en servidor con cookie segura, protección CSRF, cabeceras de seguridad, autorización por objeto, límites contra bombas ZIP y cuotas por usuario, tomando como referencia OWASP ASVS 5.0 nivel 2.
- Respaldar con datos la calidad del producto: integración continua con más de 210 pruebas de backend y 90 de la web, análisis estático externo (SonarCloud, Semgrep y Snyk) y un benchmark reproducible frente a Bandit y Semgrep CE sobre OWASP Benchmark for Python.

## Riesgos

- Límites del plan gratuito de Render (512 MB de RAM, 0,1 CPU y suspensión tras 15 minutos sin uso): la primera visita puede tardar uno o dos minutos y los escaneos grandes son más lentos. Se mitiga con límites de tamaño de entrada, análisis en un proceso hijo con tiempo límite de 300 s (al agotarse devuelve un resultado parcial), caché por contenido y la opción de escalar al plan Starter o instalar la aplicación en un servidor de la universidad.
- Reinicio o caída del worker durante un escaneo: el plan gratuito puede reiniciar el contenedor en cualquier momento. El worker envía un latido y un proceso de recuperación (reaper) devuelve a la cola los escaneos sin latido durante 2 minutos, hasta 3 intentos, por lo que ningún trabajo se pierde.
- Falsos positivos o falsos negativos que confundan al estudiante: el análisis es estático, no sigue datos entre archivos y fuera de Python solo usa heurísticas. Se mitiga con casos anotados por regla, el benchmark OWASP publicado con sus debilidades (por ejemplo, inyección de comandos), la clasificación (triage) con justificación y la supresión documentada en el propio código.
- Exposición del código o de los datos de los usuarios: un fallo de seguridad en la propia herramienta sería especialmente grave. Se mitiga con inicio de sesión OIDC sin contraseñas propias, sesión en servidor, CSRF, autorización por objeto (un recurso ajeno responde 404), borrado del código subido al terminar el escaneo, secretos detectados enmascarados, secretos de configuración solo por variables de entorno y autoanálisis en la integración continua.
- Dependencia de servicios externos gratuitos (Render, Neon, Google, GitHub): un cambio en sus condiciones podría afectar la disponibilidad. Se mitiga con un despliegue portable en Docker (docker compose levanta base de datos, limitador, migraciones, API y worker) y con soporte para cualquier proveedor OIDC, lo que permite migrar a otra nube o a infraestructura propia sin cambiar el código.

## Análisis de la Situación actual

### Planteamiento del problema

- Revisión de seguridad manual o inexistente: en los cursos, la seguridad del código de los trabajos se revisa a mano, si se revisa. El docente o jefe de práctica no puede revisar cada entrega en busca de inyecciones SQL, secretos en el código o uso de funciones peligrosas, y los estudiantes no reciben retroalimentación sobre esos fallos.
- Herramientas pensadas para profesionales, no para aprender: Bandit, Semgrep o CodeQL muestran mensajes breves en inglés, sin explicar por qué el fallo es peligroso ni cómo corregirlo. Varias opciones obligan a subir el código a servicios de terceros, algo poco adecuado para trabajos académicos.
- Sin medición del progreso: no existe una forma de saber si un estudiante corrige sus fallos de una entrega a la siguiente. Cada análisis es aislado, no se conservan las decisiones sobre falsos positivos y no hay métricas de evolución.
- Base técnica frágil en la versión 0.1: el prototipo se ejecutaba en funciones serverless de Vercel (límites de 4,5 MB y 300 s), guardaba el JWT en localStorage, tenía CORS abierto, secretos con valor por defecto, usuarios de demostración con contraseña en el código, archivos ZIP sin límites e historial solo en el navegador, lo que impedía usarlo con seguridad en un curso.

### Consideraciones de hardware y software

**Hardware:**

- Procesador: Intel Core i5 o AMD Ryzen 5 (o superior) en los equipos de desarrollo, suficiente para ejecutar en paralelo los contenedores de PostgreSQL, Valkey, API y worker, el servidor de desarrollo de la web y las pruebas.
- Memoria RAM: 16 GB recomendados para Docker, la batería de pruebas en SQLite y PostgreSQL y la ejecución del benchmark frente a Bandit y Semgrep CE.
- Almacenamiento: SSD de 512 GB para el repositorio, las imágenes Docker, el corpus anotado y los casos de OWASP Benchmark for Python.
- Conectividad: acceso estable a internet para GitHub, GitHub Actions, descarga de dependencias y despliegue en Render y Neon.
- Servidor de producción: contenedor en Render (plan gratuito: 512 MB de RAM y 0,1 CPU) con web y worker en el mismo contenedor, base de datos PostgreSQL en Neon (1 GB) y Render Key Value para el limitador de peticiones. Alternativa: cualquier servidor con Docker, por ejemplo uno de la universidad.
- Equipos cliente: cualquier computadora con un navegador moderno; no requiere instalar software. Para la línea de comandos basta Python 3.12 o la imagen Docker del proyecto.
**Software:**

- Motor de análisis: Python 3.12 con análisis de árbol sintáctico (AST), análisis de taint entre funciones del mismo archivo, reglas YAML heurísticas para JavaScript/TypeScript, PHP, Java, Kotlin, Go, Ruby, C# y HTML/Vue/Svelte, e informes SARIF 2.1.0, JSON y HTML. CLI python -m sast (scan, rules, test-rules, bench).
- Backend: Flask con arquitectura MVC (modelos SQLAlchemy 2, serializadores y vista de la SPA, blueprints finos sobre servicios) y API REST /api/v1 documentada en OpenAPI. Servidor de aplicaciones Gunicorn.
- Base de datos: PostgreSQL 16 con migraciones Alembic (11 tablas); la cola de escaneos usa SELECT … FOR UPDATE SKIP LOCKED. Valkey o Redis para el limitador de peticiones.
- Frontend: React 19, TypeScript, Vite, Tailwind CSS y shadcn/ui, servida por el mismo servidor (mismo origen), con gráficas de métricas y atajos de teclado.
- Seguridad: inicio de sesión OIDC con Google (PKCE, state y nonce) o cualquier proveedor OIDC, sesión en servidor con cookie __Host- HttpOnly Secure SameSite=Strict, CSRF, cabeceras CSP y HSTS, auditoría solo de inserción.
- Control de versiones y calidad: Git y GitHub; GitHub Actions ejecuta las pruebas (SQLite y PostgreSQL 16), lint, Vitest y build de la web, autoanálisis con SAST Studio y Bandit, y análisis externo con SonarCloud, Semgrep y Snyk.
- Infraestructura: imagen Docker multietapa con usuario sin privilegios; producción en Render (plan gratuito) con Neon (PostgreSQL gratuito) y HTTPS provisto por la plataforma; entorno local con docker compose (db, valkey, migrate, api y worker).

## Estudio de Factibilidad

### Factibilidad Técnica

El análisis técnico demuestra la factibilidad del proyecto porque el stack elegido (Python 3.12, Flask, PostgreSQL 16, React 19 y Docker) es maduro, de código abierto y conocido por el equipo, funciona con el equipo personal del integrante y se despliega en servicios en la nube de plan gratuito. Además, la versión 0.1 ya demostró la viabilidad del motor de reglas, y el benchmark sobre OWASP Benchmark for Python (1230 casos) confirma resultados competitivos: Youden medio de +20 para SAST Studio, frente a +17 de Bandit 1.9.4 y +4 de Semgrep CE 1.100.0.

*Tabla 2: Especificaciones de Hardware para el Proyecto*

| Componente | Especificación Mínima | Sustento Técnico |
|---|---|---|
| Procesador | Intel Core i5 (10.ª gen. o superior) / AMD Ryzen 5 | Adecuado para ejecutar en paralelo los contenedores de base de datos, API y worker, la web en modo desarrollo y las pruebas. |
| Memoria RAM | 16 GB | Permite trabajar con Docker, el editor y el navegador, y ejecutar la batería de pruebas y el benchmark sin cuellos de botella. |
| Almacenamiento | SSD 512 GB | Reduce los tiempos de construcción de imágenes Docker y de análisis del corpus y del benchmark. |
| Conectividad | Internet estable | Necesario para GitHub, GitHub Actions, descarga de dependencias y despliegue en Render y Neon. |
| Servidor de producción | Render (plan gratuito, 512 MB RAM, 0,1 CPU) + Neon (PostgreSQL, 1 GB) | Medido en un contenedor con esos límites: sqlalchemy/sqlalchemy (344 archivos) en 125 s y django/django (1143 archivos) en 107 s, con un pico de 353 MB de memoria. Alternativa: servidor con Docker de la universidad. |
| Dispositivos cliente | Computadora con navegador moderno | La aplicación web no requiere instalación; la CLI funciona con Python 3.12 o con la imagen Docker. |

Fuente Elaboración Propia

Nota. Los requerimientos contemplan el equipo de desarrollo del integrante, ya disponible, y los servicios en la nube de plan gratuito usados en producción.

*Tabla 3: Características de Software (Stack Tecnológico)*

Fuente Elaboración Propia

Nota. El stack seleccionado se basa exclusivamente en tecnologías de código abierto y en servicios con plan gratuito, sin costo de licencias privativas y con alta portabilidad gracias a Docker.

### Factibilidad Económica

El estudio económico estima los recursos necesarios para desarrollar y operar SAST Studio durante las 13 semanas del semestre 2026-II y un horizonte de evaluación de 3 años. Todos los montos son estimaciones referenciales en soles: los costos de personal se valorizan con remuneraciones de referencia para egresados de Ingeniería de Sistemas, los servicios básicos con consumos prorrateados y la infraestructura con los planes publicados por Render, Neon, GitHub, SonarCloud y Snyk, cuyos planes gratuitos cubren la producción del proyecto (S/ 0). A partir de estos valores se calcula la inversión inicial (año 0), los egresos operativos anuales, los beneficios estimados, el flujo de caja a 3 años, el Valor Actual Neto (VAN), la Tasa Interna de Retorno (TIR) y la relación Beneficio/Costo (B/C).

#### Costos Generales

Los costos generales corresponden a los recursos básicos y materiales necesarios para el desarrollo del proyecto.

*Tabla 4: Costos generales de recursos*

| Recurso | Cantidad | Costo Unitario (S/.) | Costo Total (S/.) |
|---|---|---|---|
| Laptop / PC de desarrollo disponible | 2 | S/ 0,00 | S/ 0,00 |
| Material de oficina e impresión de documentación | 1 | S/ 80,00 | S/ 80,00 |
| Servicio de internet, uso parcial (3 meses) | 2 | S/ 180,00 | S/ 360,00 |
| Licencias de software (todo de código abierto) | — | S/ 0,00 | S/ 0,00 |
| Total |  |  | S/ 440,00 |

Fuente Elaboración Propia

Nota. Los equipos de desarrollo son las computadoras personales de los dos integrantes, por lo que no representan una adquisición nueva. Se computa el uso proporcional de internet (S/ 60,00 mensuales por integrante durante 3 meses = S/ 180,00 cada uno) y material de oficina para la documentación. Costos estimados.

##### Costos operativos durante el desarrollo

Estos costos corresponden a la energía eléctrica y al acondicionamiento del espacio de trabajo necesarios para que el equipo trabaje durante los 3 meses de desarrollo. Como cada integrante trabaja desde su domicilio, se valorizan de forma prorrateada.

*Tabla 5: Costos operativos durante el desarrollo*

Fuente Elaboración Propia

Nota. Consumos prorrateados durante las jornadas de desarrollo, pruebas y ejecución del benchmark, considerando unas 20 horas semanales por integrante con equipos de unos 300 W. Costos estimados.

##### Costos del ambiente

*Tabla 6: Costos del ambiente de implementación*

| Recurso | Descripción | Duración | Costo estimado | Costo Total (S/.) |
|---|---|---|---|---|
| Render (web + worker) | Contenedor web con el worker embebido, plan gratuito: 512 MB de RAM, 0,1 CPU, HTTPS y subdominio onrender.com. | 13 semanas | USD 0,00 | S/ 0,00 |
| Neon (PostgreSQL) | Base de datos PostgreSQL gestionada, plan gratuito de 1 GB por proyecto. | 13 semanas | USD 0,00 | S/ 0,00 |
| Render Key Value | Almacén en memoria para los contadores del limitador de peticiones, plan gratuito. | 13 semanas | USD 0,00 | S/ 0,00 |
| GitHub y GitHub Actions | Repositorio, revisión de cambios e integración continua. | 13 semanas | USD 0,00 | S/ 0,00 |
| SonarCloud y Snyk | Análisis estático externo de calidad, seguridad y dependencias, gratuitos para el proyecto. | 13 semanas | USD 0,00 | S/ 0,00 |
| Google OIDC | Proveedor de identidad para el inicio de sesión. | 13 semanas | USD 0,00 | S/ 0,00 |
| Total |  |  |  | S/ 0,00 |

Fuente Elaboración Propia

Nota. Toda la infraestructura de producción usa planes gratuitos, por lo que su costo es S/ 0. Si la demanda creciera, el plan Starter de Render cuesta unos USD 7 mensuales por servicio (unos S/ 26 al tipo de cambio referencial de S/ 3,75 por USD). Como la aplicación es autoalojada (Docker y PostgreSQL), también puede instalarse sin costo de licencias en un servidor de la universidad.

##### Costos de personal

Los costos de personal corresponden al esfuerzo técnico necesario para analizar, diseñar, construir, probar y desplegar SAST Studio. Al tratarse de un proyecto desarrollado por los dos integrantes del equipo, se valoriza su trabajo como costo referencial de la inversión inicial (año 0), aunque no implique un desembolso real.

*Tabla 7: Costos de personal*

Fuente Elaboración Propia

Nota. Se valora el trabajo de los 2 integrantes con una dedicación de 20 horas semanales cada uno durante las 13 semanas del proyecto (unas 260 horas por persona, aproximadamente S/ 17 por hora). La remuneración mensual es una referencia estimada para egresados recientes de Ingeniería de Sistemas en el Perú.

##### Costos totales del desarrollo del sistema

Consolida todas las partidas presupuestadas para la ejecución del proyecto, que constituyen el flujo de salida del año 0 (inversión inicial) por un monto total estimado de S/ 10.160,00, el cual se contrasta con los beneficios estimados por el uso de la herramienta en los cursos:

*Tabla 8: Resumen Consolidado de la Inversión Inicial de Desarrollo (Año 0)*

Fuente Elaboración Propia

Nota. Representa la inversión inicial estimada para entregar la solución: desarrollo, pruebas, documentación y puesta en marcha en Render y Neon. Valores consolidados a partir de las Tablas 4, 5, 6 y 7 de este informe; la mayor parte corresponde a la valorización del trabajo del equipo.

#### Criterios de Inversión

Justificación de la inversión: la inversión es baja porque la infraestructura de producción cuesta S/ 0 y el software es de código abierto; casi todo el monto corresponde al trabajo del equipo. A cambio, la universidad obtiene una herramienta propia, didáctica y autoalojada, que reduce el tiempo que docentes y jefes de práctica dedican a revisar la seguridad del código de los trabajos, sin enviar ese código a terceros y sin pagar licencias.

Los costos operacionales son los gastos recurrentes para mantener el sistema en producción cada año. Como el alojamiento usa planes gratuitos (Render, Neon y Render Key Value) y el subdominio onrender.com incluye HTTPS, el único egreso recurrente estimado es el mantenimiento: actualizar dependencias, revisar alertas de Snyk y SonarCloud y ampliar o ajustar reglas, con una bolsa de 4 horas mensuales a S/ 25,00 por hora (S/ 100,00 mensuales), lo que da un costo anual de S/ 1.200,00.

*Tabla 9: Costos Operacionales Anuales de Puesta en Producción (Egresos Recurrentes)*

| Concepto Operacional | Costo Unitario Mensual (S/.) | Cantidad | Subtotal Mensual (S/.) | Total Anual (12 Meses) |
|---|---|---|---|---|
| Render web (plan gratuito) | S/ 0,00 | 1 | S/ 0,00 | S/ 0,00 |
| Neon PostgreSQL (plan gratuito) | S/ 0,00 | 1 | S/ 0,00 | S/ 0,00 |
| Render Key Value (plan gratuito) | S/ 0,00 | 1 | S/ 0,00 | S/ 0,00 |
| GitHub Actions, SonarCloud y Snyk | S/ 0,00 | 1 | S/ 0,00 | S/ 0,00 |
| Mantenimiento de reglas y dependencias (4 h/mes) | S/ 100,00 | 1 | S/ 100,00 | S/ 1.200,00 |
| Total Egresos Operacionales |  |  | S/ 100,00 | S/ 1.200,00 |

Fuente Elaboración Propia

Nota. Estimación. Si se pasara al plan Starter de Render (unos S/ 26 mensuales por servicio), el egreso anual subiría en unos S/ 312 por servicio; esta opción no se incluye porque los planes gratuitos cubren el uso previsto en los cursos. Instalarlo en un servidor de la universidad tampoco añade costo de licencias.

Beneficios tangibles: en un proyecto académico de software educativo, los beneficios se expresan como horas de trabajo ahorradas. El supuesto principal es el ahorro de horas de revisión manual de seguridad en los cursos: 2 cursos por semestre × 35 estudiantes × 3 entregas × 2 semestres = 420 revisiones al año; con SAST Studio cada revisión requiere unos 30 minutos menos, valorizados a S/ 20,00 por hora de docente o jefe de práctica. Se trata de una estimación, no de un ingreso real.

*Tabla 10: Beneficios cuantitativos anuales estimados (horas ahorradas)*

Fuente Elaboración Propia

Nota. Memoria de cálculo (estimación): 1) Revisión: el análisis automático y la explicación de cada hallazgo reducen a la mitad el tiempo de revisar la seguridad de una entrega. 2) Asesorías: la explicación didáctica (qué ocurre, cómo corregirlo, ejemplo corregido) responde dudas frecuentes sin intervención del docente. 3) Material: el catálogo de 22 reglas con ejemplos vulnerables y corregidos sirve como material de laboratorio. Todas las horas se valorizan a S/ 20,00.

Beneficios intangibles: aprendizaje de la programación segura a partir del propio código del estudiante; hábito de corregir y medir el progreso entre entregas; confidencialidad del código, que no sale del servidor; material de estudio reutilizable (reglas con casos anotados); reproducibilidad de los resultados gracias al benchmark publicado; y una base para proyectos de investigación o tesis sobre análisis estático.

El flujo de caja proyecta el comportamiento financiero del proyecto durante un horizonte de evaluación de 3 años (6 semestres de uso en los cursos). Se aplica una tasa de descuento o Costo de Oportunidad del Capital (COK) del 5,00 % anual, valor referencial cercano al rendimiento de los depósitos a plazo fijo en soles del sistema financiero peruano, que representa una alternativa de inversión segura. Con esta tasa se determinan el Valor Actual Neto (VAN), la Tasa Interna de Retorno (TIR), la relación Beneficio/Costo (B/C) y el periodo de recuperación de la inversión. Todos los resultados son estimaciones basadas en los supuestos de las Tablas 8, 9 y 10.

*Tabla 11: Flujo de caja proyectado a tres años con tasa de descuento del 5 %*

Fuente Elaboración Propia

Nota. El flujo neto anual constante de S/ 5.000,00 resulta de restar los egresos operacionales de S/ 1.200,00 a los beneficios estimados de S/ 6.200,00 por horas ahorradas. El total de egresos no incluye la inversión del año 0.

*Tabla 12: Indicadores de Rentabilidad Financiera del Proyecto con COK del 5 %*

Fuente Elaboración Propia

Nota. Estimación. Los tres indicadores superan su valor de referencia: el VAN es positivo, la TIR es mayor que el COK del 5,00 % y la relación B/C es mayor que 1. El periodo de recuperación es de unos 24 meses. La B/C se calcula como el valor presente de los beneficios (S/ 16.884,14) entre la inversión más el valor presente de los egresos (S/ 10.160,00 + S/ 3.267,90 = S/ 13.427,90).

**4.2.2.1 Valor Actual Neto (VAN)**

El Valor Actual Neto representa el valor económico adicional que genera el proyecto tras recuperar la inversión inicial, descontando los flujos netos futuros a una tasa del 5,00 % (COK). Si el VAN es mayor que cero, la propuesta es económicamente viable.

Los beneficios anuales estimados por horas ahorradas alcanzan S/ 6.200,00 frente a egresos recurrentes de S/ 1.200,00, con un flujo neto anual constante de S/ 5.000,00. Al descontar estos flujos durante tres años al 5,00 % (factor 2,7232) se obtiene un valor presente de S/ 13.616,24. Al restar la inversión inicial de S/ 10.160,00, el VAN resultante es de S/ 3.456,24.

Este resultado positivo indica que, con los supuestos indicados, el proyecto recupera la inversión inicial y genera un valor adicional durante el periodo de evaluación. El resultado depende sobre todo del número de cursos que adopten la herramienta: si los beneficios fueran un 25 % menores (S/ 4.650,00 al año), el VAN sería de unos S/ -765; con un curso más por semestre, el VAN aumentaría.

##### 4.2.2.2 Tasa Interna de Retorno (TIR)

La Tasa Interna de Retorno indica la rentabilidad porcentual del capital invertido. Si la TIR es mayor que el costo de oportunidad del capital, el proyecto se acepta; si es igual, la decisión es indiferente; y si es menor, el proyecto se rechaza.

Para SAST Studio, la TIR estimada es de aproximadamente 22,3 %, superior al COK del 5,00 %. La relación Beneficio/Costo es de 1,26: por cada sol invertido o gastado se obtienen, en valor presente, 1,26 soles en horas de trabajo ahorradas.

Con un flujo neto anual de S/ 5.000,00 frente a la inversión inicial de S/ 10.160,00, el periodo de recuperación es de 2,03 años (unos 24 meses), es decir, la inversión se recupera durante el tercer año de uso.

### Factibilidad Operativa

La factibilidad operativa de SAST Studio es alta porque se adapta a la forma en que ya trabajan estudiantes y docentes en los cursos de programación y seguridad:

- Acceso sin instalación ni contraseñas nuevas: la aplicación web funciona en cualquier navegador y el usuario entra con su cuenta de Google mediante OIDC. Para integrarla en un pipeline basta la CLI (python -m sast scan) o la imagen Docker.
- Flujo de trabajo simple: el usuario crea un proyecto y escanea código pegado, un ZIP o un repositorio público de GitHub; sigue el progreso en la cola, puede cancelar y revisa los resultados con filtros, búsqueda y atajos de teclado.
- Aprendizaje integrado: cada hallazgo muestra el código afectado, el recorrido del dato, la explicación didáctica y un ejemplo corregido; los informes se exportan en SARIF, JSON o HTML para entregarlos o integrarlos en GitHub.
- Seguimiento sin trabajo adicional: el sistema calcula qué hallazgos son nuevos, persistentes, corregidos o reabiertos, conserva la clasificación (triage) y muestra métricas de evolución, lo que permite al docente comprobar el progreso entre entregas. La operación (configuración, límites, copias de seguridad) la realiza el Administrador del Sistema mediante variables de entorno.

### Factibilidad Legal

El proyecto es legalmente viable y se ajusta a la normativa peruana de protección de datos y a las licencias del software que usa o con el que se compara:

- Ley N.° 29733, Ley de Protección de Datos Personales, y su reglamento: el sistema solo guarda el correo y el nombre del usuario (junto con el identificador que entrega el proveedor de identidad) y no almacena contraseñas. El código subido (ZIP o código pegado) se borra al terminar el escaneo, los secretos detectados se guardan enmascarados, las ocurrencias se purgan a los 90 días y cada usuario solo accede a sus propios proyectos.
- Licencia del proyecto: SAST Studio se distribuye con licencia MIT (declarada en pyproject.toml), lo que permite a la universidad y a terceros usarlo, modificarlo e instalarlo en sus propios servidores.
- Licencias de las dependencias: el producto se construye con componentes de código abierto con licencias permisivas compatibles con MIT (por ejemplo, Flask con licencia BSD, React con licencia MIT y PostgreSQL con su propia licencia permisiva), sin licencias privativas.
- Herramientas comparadas y benchmark: Bandit (licencia Apache-2.0) y Semgrep CE se usan solo como competidores en el benchmark y no se incrustan en el producto; las reglas públicas de Semgrep tienen una licencia restrictiva, por lo que se descargan para la medición y no se redistribuyen. OWASP Benchmark for Python (GPL-3.0) también se descarga al medir y no se copia en el repositorio.
- Uso de servicios externos: el inicio de sesión con Google y la descarga de repositorios públicos de GitHub se realizan según las condiciones de uso de esos servicios; el sistema solo descarga repositorios públicos y nunca ejecuta el código analizado, que se lee como texto.

### Factibilidad Social

SAST Studio genera un impacto social positivo en la formación de los estudiantes de la Escuela Profesional de Ingeniería de Sistemas y de quienes aprenden a programar de forma segura:

- Aprender con el propio código: el estudiante ve explicado cada fallo sobre el código que él mismo escribió, con su corrección y referencias CWE y OWASP, lo que acerca la seguridad del software a estudiantes de los primeros ciclos.
- Retroalimentación inmediata y medible: el estudiante descubre y corrige sus propios fallos sin esperar la revisión del docente y puede ver su progreso entre escaneos, lo que fomenta el hábito de programar de forma segura.
- Acceso libre y confidencial: al ser gratuito, de código abierto y autoalojable, cualquier curso o institución puede usarlo sin costo y sin entregar el código de sus estudiantes a terceros, lo que contribuye a formar profesionales más conscientes de la seguridad.

### Factibilidad Ambiental

El proyecto presenta una factibilidad ambiental favorable por el uso eficiente de recursos de cómputo y la ausencia de papel:

- Infraestructura en la nube compartida: la producción usa contenedores y bases de datos compartidos de plan gratuito (Render y Neon), que se suspenden cuando no hay uso (a los 15 y 5 minutos, respectivamente), por lo que no se mantiene encendido un servidor dedicado. La caché de resultados por contenido evita repetir análisis idénticos.
- Autoalojable y sin papel: la misma imagen Docker puede instalarse en un servidor que la universidad ya tenga, sin comprar hardware nuevo; además, las revisiones, informes y métricas son digitales (SARIF, JSON y HTML), lo que evita imprimir reportes de revisión.

## Conclusiones

Técnicamente, el proyecto es factible porque utiliza un stack maduro y de código abierto (Python 3.12, Flask con arquitectura MVC, PostgreSQL 16, React 19 y Docker), funciona con los equipos ya disponibles y su motor obtiene un Youden medio de +20 en OWASP Benchmark for Python, por encima de Bandit (+17) y Semgrep CE (+4).

Económicamente, el proyecto requiere una inversión inicial estimada de S/ 10.160,00, casi toda correspondiente a la valorización del trabajo de los dos integrantes, ya que la infraestructura de producción en Render, Neon, GitHub, SonarCloud y Snyk cuesta S/ 0.

Financieramente, con los supuestos de horas de revisión ahorradas en los cursos, la propuesta presenta un VAN estimado de S/ 3.456,24, una TIR de 22,3 % y una relación Beneficio/Costo de 1,26, superiores a la tasa de descuento del 5,00 %, con recuperación de la inversión en unos 24 meses.

Operativamente, la herramienta se usa desde el navegador con la cuenta de Google o desde la línea de comandos, explica cada hallazgo y cómo corregirlo, y mide el progreso entre escaneos sin trabajo adicional para el docente.

Legalmente, el sistema cumple la Ley N.° 29733 al guardar solo el correo y el nombre del usuario y borrar el código subido al terminar el escaneo; se distribuye con licencia MIT y respeta las licencias de las herramientas comparadas, que no se redistribuyen.

Social y ambientalmente, el proyecto acerca la formación en programación segura a los estudiantes y usa infraestructura en la nube compartida o autoalojada, sin hardware dedicado nuevo ni papel.

Por lo tanto, se concluye que el proyecto es viable en todas sus dimensiones y se recomienda completar su desarrollo y ponerlo a disposición de los cursos de la Escuela Profesional de Ingeniería de Sistemas en el semestre 2026-II.
