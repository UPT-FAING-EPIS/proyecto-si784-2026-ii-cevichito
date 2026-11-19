# FD02 · Informe de Visión

> Versión en Markdown del documento `FD02-EPIS-Informe Vision.docx` (el Word es la versión oficial, con portada, índice e imágenes).

![Imagen 1](media/md/fd02-imagen-1.png)

**UNIVERSIDAD PRIVADA DE TACNA**

**FACULTAD DE INGENIERÍA**

**Escuela Profesional de Ingeniería de Sistemas**

**SAST Studio: Analizador Estático de Seguridad Didáctico y Autoalojado**

Curso: CALIDAD Y PRUEBAS DE SOFTWARE (SI-784)

Docente: Mg. Ing. Patrick José Cuadros Quiroga

Integrantes:

**Sagua Ramos, Gustavo Alonso** **2018062254**

**Serrano Ibañez, Nestor Juice Yomar** **2022075747**

**Tacna – Perú**

**2026**

| CONTROL DE VERSIONES |  |  |  |  |  |
|---|---|---|---|---|---|
| Versión | Hecha por | Revisada por | Aprobada por | Fecha | Motivo |
| 1.0 | SRGA, SINJ |  |  | 14/11/2026 | Versión original |

## SAST Studio: Analizador Estático de Seguridad Didáctico y Autoalojado

## Documento de Visión

## Versión 1.0

| CONTROL DE VERSIONES |  |  |  |  |  |
|---|---|---|---|---|---|
| Versión | Hecha por | Revisada por | Aprobada por | Fecha | Motivo |
| 1.0 | SRGA, SINJ |  |  | 14/11/2026 | Versión original |

**Índice**

- SAST Studio: Analizador Estático de Seguridad Didáctico y Autoalojado
- Documento de Visión
- Versión 1.0
- Introducción
  - Propósito
  - Alcance
  - Definiciones, Siglas y Abreviaturas
  - Referencias
  - Visión General
- Posicionamiento
  - Oportunidad de negocio
  - Definición del problema
- Descripción de los interesados y usuarios
  - Resumen de los interesados
  - Resumen de los usuarios
  - Entorno de usuario
  - Perfiles de los interesados
  - Perfiles de los Usuarios
  - Necesidades de los interesados y usuarios
- Vista General del Producto
  - Perspectiva del producto
  - Resumen de capacidades
  - Suposiciones y dependencias
  - Costos y precios
  - Licenciamiento e instalación
- Características del producto
- Restricciones
- Rangos de calidad
- Precedencia y Prioridad
- Otros requerimientos del producto
- CONCLUSIONES
- RECOMENDACIONES
- BIBLIOGRAFÍA
- WEBGRAFÍA

## Introducción

Los cursos de programación y de seguridad de software necesitan que los estudiantes aprendan a reconocer y corregir vulnerabilidades como la inyección SQL, la inyección de comandos o el uso de criptografía débil. Las herramientas de análisis estático de seguridad (SAST) disponibles, como Bandit, Semgrep, SonarQube o CodeQL, están pensadas para equipos de seguridad: informan con mensajes breves en inglés, no explican cómo corregir el fallo y, en su versión en la nube, obligan a subir el código a servicios de terceros. Además, ninguna de ellas permite a un docente ver de forma sencilla si un estudiante corrige sus fallos de un trabajo al siguiente.

El presente Documento de Visión establece los requisitos de alto nivel, los interesados, las capacidades y las restricciones de SAST Studio, una aplicación web y de línea de comandos, autoalojada con Docker y PostgreSQL, que analiza código fuente en busca de vulnerabilidades (OWASP Top 10 / CWE), explica cada hallazgo y cómo corregirlo, y mide el progreso entre escaneos. El proyecto parte de una versión 0.1 frágil y la refactoriza con criterios de calidad (ISO/IEC 25010) y de seguridad (OWASP ASVS 5.0 nivel 2) dentro del curso Calidad y Pruebas de Software.

### Propósito

El propósito de este documento es definir la visión de SAST Studio: qué problema resuelve, para quién, qué capacidades ofrece y qué límites tiene. Sirve de referencia común para el equipo de desarrollo, el docente del curso y los futuros usuarios, y es la base de la que se derivan la especificación de requisitos (FD03), la arquitectura (FD04) y el informe final (FD05). Define los límites del producto, los actores, las capacidades técnicas y los criterios de calidad que guían su ciclo de vida.

### Alcance

SAST Studio abarca el ciclo completo de un análisis de seguridad con fines didácticos: desde que el usuario inicia sesión y entrega su código (pegado, en un ZIP o como repositorio público de GitHub) hasta que revisa los hallazgos explicados, los clasifica, exporta el informe y compara el resultado con escaneos anteriores del mismo proyecto. Incluye también la línea de comandos para integrar el análisis en un pipeline de integración continua.

En Alcance (In-Scope):

- Seguridad y Acceso (P01): inicio de sesión con Google mediante OIDC con PKCE, state y nonce; sesión en el servidor con cookie __Host-, protección CSRF, cierre de sesión y consulta de la configuración pública.
- Gestión de Proyectos (P02): creación, renombrado y eliminación en cascada de proyectos, y panel con el último escaneo y los hallazgos abiertos por severidad de cada uno.
- Escaneo de Código (P03): análisis de código pegado, de archivos ZIP validados contra bombas ZIP y rutas maliciosas, y de repositorios públicos de GitHub; selección de reglas, seguimiento del progreso y cancelación.
- Resultados y Aprendizaje (P04): tabla de hallazgos con filtros, explicación didáctica de cada hallazgo con recorrido del dato, ejemplos vulnerable y corregido, catálogo de las 22 reglas y exportación a SARIF 2.1.0, JSON y HTML.
- Seguimiento de Hallazgos (P05): comparación con el escaneo anterior (nuevos, corregidos, reabiertos), clasificación (triage) que se conserva entre escaneos, comentarios e historial, métricas (MTTR, densidad por KLOC) y supresión justificada desde el propio código.
- Motor, Integración y Operación (P06): worker que procesa la cola en segundo plano con prioridad, turnos y caché por contenido; recuperación de escaneos interrumpidos, comprobación de salud (/healthz y /readyz) y purga de datos antiguos; CLI para CI/CD; reglas ampliables en Python o YAML con casos anotados y benchmark reproducible frente a Bandit y Semgrep CE.
- Retos de Corrección (P07): ocho retos con código vulnerable preparado (inyección SQL, inyección de comandos, path traversal, XSS, contraseñas con MD5, secreto en el código, eval y pickle), editor en el navegador, pistas que se revelan de una en una y verificación automática: el reto se supera solo si la regla ya no detecta el fallo, sin silenciarlo, y no aparece ningún hallazgo grave nuevo.
Fuera de Alcance (Out-of-Scope):

- Análisis de taint entre archivos: el seguimiento del dato es entre funciones, pero dentro de cada archivo; fuera de Python solo hay reglas heurísticas de confianza baja.
- Ejecución del código analizado, análisis dinámico (DAST) o pruebas de penetración: el código solo se lee como texto.
- Análisis de dependencias de terceros (SCA) y búsqueda de CVE en librerías.
- Repositorios privados de GitHub, roles diferenciados (RBAC) y gestión académica de cursos o notas: existe un único rol de usuario y cada usuario solo accede a sus propios proyectos.
- Uso como escáner de producción o herramienta de cumplimiento normativo (PCI DSS, ISO 27001), y corrección automática del código: SAST Studio explica cómo corregir, pero la corrección la hace la persona.

### Definiciones, Siglas y Abreviaturas

Para entender el sistema, es necesario definir estos términos clave:

- SAST (Static Application Security Testing): análisis de seguridad que examina el código fuente sin ejecutarlo para encontrar patrones vulnerables.
- OWASP (Open Worldwide Application Security Project): fundación que publica el OWASP Top 10 (las diez categorías de riesgo más críticas en aplicaciones web, edición 2021), el estándar ASVS y el OWASP Benchmark.
- ASVS (Application Security Verification Standard): estándar de OWASP con requisitos de seguridad verificables por niveles; SAST Studio toma como objetivo la versión 5.0, nivel 2.
- CWE (Common Weakness Enumeration): catálogo de tipos de debilidades de software mantenido por MITRE (por ejemplo, CWE-89 inyección SQL); cada regla de SAST Studio indica sus CWE.
- SARIF (Static Analysis Results Interchange Format): formato estándar de OASIS, versión 2.1.0, para intercambiar resultados de análisis estático; lo leen GitHub Code Scanning y DefectDojo.
- OIDC (OpenID Connect): capa de identidad sobre OAuth 2.0 que permite iniciar sesión con un proveedor externo, como Google, y obtener un id_token firmado.
- PKCE (Proof Key for Code Exchange): extensión de OAuth definida en el RFC 7636 que impide que un código de autorización interceptado pueda canjearse por un token.
- CSRF (Cross-Site Request Forgery): ataque que hace que el navegador de un usuario autenticado envíe peticiones no deseadas; se evita con un token CSRF y la comprobación del origen.
- Análisis de taint: técnica que sigue un dato no confiable desde una fuente (por ejemplo, request.args) hasta un sink peligroso (una consulta SQL, un comando del sistema), salvo que pase por un sanitizador.
- AST (Abstract Syntax Tree): árbol sintáctico del programa; las reglas de Python lo recorren en lugar de buscar texto.
- Hallazgo, issue y ocurrencia: un hallazgo es cada aviso de una regla; el issue es el problema persistente de un proyecto y la ocurrencia es su aparición en un escaneo concreto.
- Huella (fingerprint) sastfp/v1: identificador estable de un issue calculado con la regla, la ruta y el contenido normalizado, sin número de línea, para que mover el código no cree un issue nuevo.
- Clasificación (triage): decisión de una persona sobre un issue: confirmado, falso positivo, riesgo aceptado o no se corregirá; mientras nadie decide, el issue queda «sin revisar».
- MTTR (Mean/Median Time To Remediate): tiempo que tarda en corregirse un hallazgo; SAST Studio muestra la mediana.
- KLOC: mil líneas de código; la densidad de hallazgos se expresa por cada KLOC.
- CI/CD (Integración y Entrega Continuas): práctica de compilar, probar y desplegar automáticamente en cada cambio; SAST Studio se integra mediante su CLI y el formato SARIF.
- Worker y reaper: el worker es el proceso que ejecuta los escaneos en segundo plano; el reaper devuelve a la cola los escaneos de un worker que dejó de enviar latido.
- Índice de Youden: métrica del OWASP Benchmark, igual a la tasa de verdaderos positivos menos la tasa de falsos positivos; 0 indica que la herramienta no distingue lo vulnerable de lo seguro y +100 es perfecto.
- Autoalojado (self-hosted): instalado en un servidor propio, de modo que el código analizado no sale de la organización.

### Referencias

Las normas, estándares y especificaciones técnicas en los que se basa este documento se citan en estilo APA 7.ª edición:

- OWASP Foundation. (2021). OWASP Top 10:2021. https://owasp.org/Top10/
- MITRE Corporation. (s. f.). Common Weakness Enumeration (CWE). https://cwe.mitre.org/
- OWASP Foundation. (2025). OWASP Application Security Verification Standard (ASVS) 5.0.0. https://owasp.org/www-project-application-security-verification-standard/
- OASIS. (2020). Static Analysis Results Interchange Format (SARIF) Version 2.1.0. OASIS Standard. https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- International Organization for Standardization. (2023). ISO/IEC 25010:2023. Systems and software engineering — Systems and software Quality Requirements and Evaluation (SQuaRE) — Product quality model. ISO.
- Sakimura, N., Bradley, J., & Agarwal, N. (2015). Proof Key for Code Exchange by OAuth Public Clients (RFC 7636). Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc7636
- Sakimura, N., Bradley, J., Jones, M., de Medeiros, B., & Mortimore, C. (2014). OpenID Connect Core 1.0. OpenID Foundation. https://openid.net/specs/openid-connect-core-1_0.html
- OWASP Foundation. (s. f.). OWASP Benchmark for Python. https://github.com/OWASP-Benchmark/BenchmarkPython

### Visión General

Este documento de visión se organiza en secciones para detallar la estructura, justificación y características de SAST Studio.

- Sección 1: Introducción: Presenta el propósito, el alcance, las definiciones y las referencias del documento.
- Sección 2: Posicionamiento: Describe la oportunidad frente a las herramientas SAST existentes y delimita el problema que se resuelve.
- Sección 3: Descripción de los interesados y usuarios: Detalla los perfiles de estudiantes, docentes, administradores y desarrolladores de reglas, y sus necesidades.
- Sección 4: Vista General del Producto: Presenta la perspectiva general, el resumen de capacidades, las suposiciones, las dependencias, los costos y el licenciamiento.
- Sección 5: Características del producto: Agrupa los requisitos funcionales RF-01 a RF-28 en los siete paquetes del sistema.
- Secciones 6 a 9: Definen las restricciones del producto, los rangos de calidad (RNF por ISO/IEC 25010), la priorización de requisitos con MoSCoW y los estándares legales, de comunicación, de plataforma, de calidad y de seguridad.

## Posicionamiento

### Oportunidad de negocio

El mercado gratuito de herramientas SAST ya está ocupado en la capa de detección: Bandit analiza Python con reglas sobre el árbol sintáctico; Semgrep Community Edition ofrece reglas públicas para muchos lenguajes y un plan gratuito en la nube; SonarQube Community Build ofrece un panel autoalojado, pero sin análisis de taint, que queda en las ediciones de pago; y CodeQL ofrece análisis semántico profundo, gratuito solo para repositorios públicos. SAST Studio no compite en capacidad de detección. Su oportunidad está en un hueco estrecho pero real: una herramienta gratuita, autoalojada y ligera, pensada para enseñar, que explica cada hallazgo y cómo corregirlo, mide el progreso del estudiante entre escaneos y tiene reglas pequeñas y legibles que sirven como material de estudio.

Esa propuesta se respalda con datos medidos y no con afirmaciones: en el OWASP Benchmark for Python (1230 casos), SAST Studio obtiene una media de Youden de +20, frente a +17 de Bandit 1.9.4 y +4 de Semgrep CE 1.100.0 con reglas públicas, y +100 en inyección SQL. También se publican sus debilidades: inyección de comandos (−46), XSS (−7) y path traversal (+4), y no sigue datos entre archivos. Semgrep Pro y CodeQL no se evaluaron, por lo que no se afirma que SAST Studio detecte más que ellos. Para la Escuela Profesional de Ingeniería de Sistemas, la oportunidad es contar con una herramienta propia que puede instalarse gratis en un servidor de la universidad sin enviar el código de los estudiantes a terceros.

### Definición del problema

El problema de: la falta de una herramienta de análisis estático de seguridad que enseñe: las disponibles dan avisos breves en inglés sin explicar cómo corregirlos, obligan en muchos casos a subir el código a servicios externos y no permiten medir si un estudiante corrige sus fallos de un trabajo al siguiente.

Afecta a: estudiantes y docentes de cursos de programación y seguridad, y a desarrolladores que aprenden seguridad por su cuenta.

El impacto de esto es: vulnerabilidades que se repiten de un trabajo a otro, revisiones manuales que consumen tiempo del docente, exposición del código de los estudiantes a terceros y una versión 0.1 del propio proyecto frágil (Vercel serverless con límites de 4,5 MB y 300 s, JWT en localStorage, CORS abierto, secretos con valor por defecto, usuarios demo con contraseña en el código, ZIP sin límites e historial solo en el navegador).

Una solución exitosa debería: explicar cada hallazgo con su corrección y ejemplos, conservar el historial y la clasificación de cada hallazgo entre escaneos, ejecutarse en un servidor propio con PostgreSQL y un worker en segundo plano, y cumplir prácticas de seguridad verificables (OWASP ASVS 5.0 nivel 2).

## Descripción de los interesados y usuarios

### Resumen de los interesados

*Tabla 1: Identificación y caracterización de interesados (Stakeholders)*

| Nombre | Descripción | Responsabilidades |
|---|---|---|
| Escuela Profesional de Ingeniería de Sistemas – UPT | Organización usuaria en la que se emplea la herramienta dentro de los cursos de programación y de calidad. | Proveer el contexto académico, validar el uso didáctico de la herramienta y, si lo decide, alojar una instancia en un servidor propio. |
| Docentes de cursos de programación y seguridad | Profesores que proponen trabajos y revisan el código de sus estudiantes. | Usar los informes, el catálogo de reglas y las métricas para orientar y evaluar el progreso. |
| Estudiantes y desarrolladores | Personas que escriben código y aprenden a reconocer y corregir vulnerabilidades. | Escanear su código, estudiar las explicaciones, corregir y clasificar los hallazgos. |
| Equipo de desarrollo (SRGA, SINJ) | Integrantes del proyecto en el curso Calidad y Pruebas de Software. | Construir, probar, documentar y desplegar SAST Studio, y mantener el catálogo de reglas y el benchmark. |
| Administrador del Sistema | Responsable técnico de la instalación (Render + Neon o Docker en un servidor propio). | Configurar variables de entorno, límites y proveedor OIDC, vigilar la disponibilidad y las copias de seguridad de la base de datos. |

Fuente Elaboración Propia

Nota. La matriz delimita los interesados directos e indirectos del proyecto, asegurando la correspondencia entre los objetivos didácticos y los requisitos funcionales del software.

### Resumen de los usuarios

*Tabla 2: Resumen y clasificación de perfiles de usuario del sistema*

| Nombre | Descripción | Responsabilidades |
|---|---|---|
| Usuario (Estudiante / Desarrollador) | Persona autenticada con Google; los docentes usan la misma cuenta de usuario. | Crear proyectos, lanzar escaneos, revisar y clasificar hallazgos, comentar, exportar informes y consultar métricas de sus propios proyectos. |
| Administrador del Sistema | Opera la instalación; no tiene pantallas propias, trabaja por configuración y con la CLI. | Desplegar la imagen Docker, definir secretos y límites por variables de entorno, configurar el proveedor OIDC y respaldar la base de datos. |
| Desarrollador de Reglas | Usuario técnico que amplía el motor de análisis. | Escribir reglas en Python o YAML con casos anotados, validarlas con sast test-rules y medir su precisión con sast bench. |

Fuente Elaboración Propia

Nota. La aplicación tiene un único rol de usuario (no hay RBAC): cada usuario solo accede a sus propios proyectos y un recurso ajeno responde 404. Los sistemas externos (Google OIDC, GitHub, pipeline CI/CD) y el Worker de Análisis interactúan con el sistema, pero no son usuarios humanos.

### Entorno de usuario

Aplicación web de acceso autenticado servida por HTTPS desde un único origen (la misma aplicación sirve la interfaz y la API). No hay registro con contraseña: el usuario entra con su cuenta de Google y obtiene una sesión en el servidor. Está publicada en https://sast-studio.onrender.com y puede instalarse en cualquier servidor con Docker.

- Equipos de escritorio y portátiles: el uso principal es desde un navegador moderno en laboratorios de la universidad o en casa, con una interfaz en español y atajos de teclado en la tabla de hallazgos.
- Terminal y pipeline de integración continua: estudiantes, desarrolladores de reglas y pipelines CI/CD usan la CLI python -m sast para escanear localmente o en GitHub Actions y publicar el SARIF.
- Servidor: en producción, un contenedor en Render (plan gratuito, 512 MB de RAM, 0,1 CPU) con la base de datos en Neon; en local o en un servidor propio, docker compose con PostgreSQL 16 y Valkey.

### Perfiles de los interesados

*Tabla 3: Matriz de perfiles de los interesados y criterios de éxito*

| Representante | Descripción | Responsabilidad | Criterio de éxito | Nivel de participación |
|---|---|---|---|---|
| Docentes | Profesores de cursos de programación, seguridad o calidad. | Proponer trabajos y revisar el avance en seguridad de sus estudiantes. | Ver en las métricas que los hallazgos corregidos aumentan y que los nuevos disminuyen entre entregas. | Medio (al revisar trabajos y preparar clases). |
| Estudiantes | Usuarios principales que aprenden seguridad con su propio código. | Escanear, entender y corregir sus hallazgos. | Comprender cada hallazgo sin recurrir a documentación en inglés y corregirlo con el ejemplo propuesto. | Alto (en cada entrega o práctica). |
| EPIS – UPT | Organización académica usuaria. | Valorar la adopción de la herramienta en sus cursos. | Disponer de una herramienta gratuita y autoalojada en la que el código no sale de la universidad. | Bajo (decisiones de adopción). |
| Equipo de desarrollo | Integrantes del proyecto (SRGA, SINJ). | Entregar el producto refactorizado y documentado. | CI en verde, benchmark reproducible y despliegue operativo en Render + Neon. | Alto y continuo durante el semestre. |

Fuente Elaboración Propia

Nota. La matriz detalla las expectativas de los grupos de interés y vincula sus criterios de éxito (comprensión del hallazgo, progreso medible y privacidad del código) con los objetivos de calidad del sistema.

### Perfiles de los Usuarios

*Tabla 4: Perfiles de los usuarios y patrones de interacción con el sistema*

Fuente Elaboración Propia

Nota. La frecuencia y el tipo de interacción determinan los requisitos no funcionales de usabilidad y eficiencia: la interfaz se orienta a equipos de escritorio y la CLI a terminales y pipelines.

### Necesidades de los interesados y usuarios

*Tabla 5: Matriz de necesidades de los interesados y usuarios del sistema*

| Nro° | Necesidad | Descripción de la Necesidad |
|---|---|---|
| N-01 | Acceso seguro sin contraseñas propias | Los usuarios necesitan entrar con su cuenta institucional o de Google, sin crear otra contraseña, con una sesión que no pueda robarse desde el navegador. |
| N-02 | Organización del trabajo por proyectos | Cada estudiante necesita agrupar los escaneos de un mismo trabajo y ver de un vistazo su estado y sus hallazgos abiertos. |
| N-03 | Análisis sin instalación desde varias entradas | Los usuarios necesitan analizar un fragmento pegado, un ZIP del proyecto o un repositorio público de GitHub desde el navegador. |
| N-04 | Seguimiento del escaneo sin bloquear la web | Los usuarios necesitan saber la posición en la cola y el progreso del escaneo, y poder cancelarlo, mientras el análisis corre en segundo plano. |
| N-05 | Explicación didáctica | Los estudiantes necesitan entender qué ocurre, por qué es peligroso y cómo corregirlo, con un ejemplo vulnerable y otro corregido, y su CWE y OWASP. |
| N-06 | Medición del progreso entre escaneos | Docentes y estudiantes necesitan ver qué hallazgos son nuevos, persisten, se corrigieron o reaparecieron, conservando la clasificación decidida. |
| N-07 | Informes en formatos estándar | Los usuarios necesitan entregar o integrar los resultados en SARIF 2.1.0, JSON o HTML, compatibles con GitHub Code Scanning y DefectDojo. |
| N-08 | Privacidad del código y operación gratuita | La organización necesita que el código no salga del servidor propio y que la herramienta pueda instalarse sin costo de licencias. |
| N-09 | Integración en CI y reglas medibles | Desarrolladores y pipelines necesitan ejecutar el análisis por línea de comandos, ampliar las reglas con casos anotados y medir su precisión con un benchmark. |
| N-10 | Practicar la corrección de vulnerabilidades | Los estudiantes necesitan ejercitarse corrigiendo fallos reales con ayuda graduada y saber, sin esperar a un revisor, si su corrección elimina el fallo. |

Fuente Elaboración Propia

Nota. Relación de necesidades de los interesados que constituyen la base para la especificación formal de los Requerimientos Funcionales (RF-01 a RF-28) y de los Casos de Uso (CUS-01 a CUS-28).

## Vista General del Producto

### Perspectiva del producto

SAST Studio es un producto independiente y autoalojado con arquitectura MVC. Se compone de un motor de análisis en Python 3.12 (sast/) con reglas sobre el árbol sintáctico, análisis de taint entre funciones del mismo archivo y reglas YAML heurísticas para JavaScript/TypeScript, PHP, Java, Kotlin, Go, Ruby, C# y plantillas HTML/Vue/Svelte; una API REST /api/v1 en Flask con modelos SQLAlchemy sobre PostgreSQL 16; un worker que procesa la cola de escaneos en segundo plano; y una interfaz web en React 19 con TypeScript servida desde el mismo origen. Se relaciona con tres sistemas externos: el proveedor de identidad (Google OIDC), GitHub como fuente de repositorios públicos y los pipelines CI/CD que consumen su CLI y el SARIF.

### Resumen de capacidades

- Inicio de sesión con Google (OIDC con PKCE) y sesión en el servidor con cookie __Host- y protección CSRF.
- Proyectos con historial de escaneos guardado en PostgreSQL, en lugar del navegador.
- Escaneo de código pegado, ZIP validado o repositorio público de GitHub, con selección de reglas, cola con prioridad, progreso y cancelación.
- 22 reglas (13 de Python, 8 heurísticas multilenguaje y 1 de secretos) con explicación didáctica, recorrido del dato, CWE y OWASP.
- Issues persistentes con huella sastfp/v1: comparación entre escaneos, clasificación que se conserva, comentarios, historial y supresión justificada en el código.
- Métricas por proyecto: abiertos por severidad, nuevos frente a corregidos, MTTR y densidad por KLOC.
- Retos de corrección: ocho ejercicios con código vulnerable, editor en el navegador, pistas y verificación automática de que el fallo desapareció sin introducir otros.
- Informes SARIF 2.1.0, JSON y HTML, y CLI python -m sast (scan, rules, test-rules, bench) para CI/CD.

### Suposiciones y dependencias

- **Conectividad:** Los usuarios necesitan conexión a internet para usar la instancia publicada; en una instalación en la red de la universidad basta con la red local, salvo para el inicio de sesión con Google y la descarga de repositorios de GitHub.
- **Proveedor de identidad:** El inicio de sesión depende de Google OIDC (o de otro proveedor OIDC configurado con OIDC_ISSUER); si el proveedor no está disponible no se puede iniciar sesión.
- **Servicios de alojamiento gratuitos:** La instancia publicada depende de los planes gratuitos de Render (web y worker en un contenedor, 512 MB de RAM, 0,1 CPU, se duerme tras 15 min sin uso) y de Neon (PostgreSQL de 1 GB); sus condiciones pueden cambiar.
- **GitHub:** El escaneo de repositorios depende de la descarga del zipball desde GitHub, con límites de tamaño y tiempo, y solo funciona con repositorios públicos.
- **Conocimientos previos:** Se asume que los usuarios conocen la programación básica; la herramienta explica la vulnerabilidad, pero no enseña el lenguaje.

### Costos y precios

- Presupuesto de desarrollo: corresponde al esfuerzo de 2 integrantes durante 13 semanas (semestre 2026-II), con equipos y servicios propios; su estimación detallada en soles figura en el Informe de Factibilidad (FD01).
- Costo de operación: S/ 0 mensuales con la configuración actual, porque Render, Neon, Render Key Value, GitHub, GitHub Actions, SonarCloud, Snyk y el proveedor Google OIDC son gratuitos para el proyecto.
- Opción de escalado (estimada): Render Starter cuesta aproximadamente 7 USD al mes por servicio (≈ S/ 26). Como alternativa, el diseño autoalojado permite instalarlo gratis en un servidor de la universidad.

### Licenciamiento e instalación

- Modelo de licencia: Software de código abierto con licencia MIT, desarrollado con fines académicos. Las reglas públicas de Semgrep no se incluyen ni se redistribuyen; Semgrep CE solo se usa como referencia en el benchmark.
- Proceso de instalación: Al ser una aplicación web, los usuarios finales no instalan nada. El administrador copia .env.example a .env, define los secretos y ejecuta docker compose up, que levanta PostgreSQL, Valkey, las migraciones, la API con la web y el worker. En Render el despliegue se describe en render.yaml. Para usar solo la CLI basta con pip install -e . y Python 3.11 o superior.

## Características del producto

Las funcionalidades del sistema, consolidadas a partir de las necesidades detectadas, se agrupan en siete paquetes que corresponden a los requisitos funcionales RF-01 a RF-28:

- P01 · Seguridad y Acceso: iniciar sesión con Google (RF-01), cerrar sesión (RF-02) y consultar la sesión, la configuración pública y los límites de escaneo en Ajustes (RF-03).
- P02 · Gestión de Proyectos: crear proyecto (RF-04), consultar el panel de proyectos (RF-05) y renombrar y eliminar proyecto con borrado en cascada y auditoría (RF-06).
- P03 · Escaneo de Código: escanear código pegado (RF-07), archivo ZIP (RF-08) y repositorio de GitHub (RF-09), con la opción de limitar el análisis a las reglas elegidas, y seguir y cancelar el escaneo (RF-10).
- P04 · Resultados y Aprendizaje: consultar los hallazgos abiertos del proyecto (RF-11), consultar los resultados de un escaneo con filtros (RF-12), ver la explicación didáctica del hallazgo (RF-13), consultar el catálogo de reglas (RF-14) y exportar el informe en SARIF, JSON o HTML (RF-15).
- P05 · Seguimiento de Hallazgos: comparar con el escaneo anterior (RF-16), clasificar el hallazgo (RF-17), comentar y consultar el historial del issue (RF-18), consultar métricas del proyecto (RF-19) y suprimir un hallazgo desde el código (RF-20).
- P06 · Motor, Integración y Operación: procesar el escaneo en segundo plano (RF-21), recuperar escaneos interrumpidos y vigilar la salud del servicio con purga de datos antiguos (RF-22), analizar desde la línea de comandos (RF-23), ampliar y probar reglas (RF-24) y medir la precisión con el benchmark (RF-25).
- P07 · Retos de Corrección: consultar los retos y el propio progreso (RF-26), resolver un reto corrigiendo el código en el editor del navegador con pistas progresivas (RF-27) y verificar la corrección comparando el envío con el código de partida (RF-28).

## Restricciones

- Alcance del análisis: el análisis de taint es entre funciones, pero dentro de cada archivo; no sigue datos entre archivos y fuera de Python solo hay heurísticas. Se omiten pruebas, dependencias y archivos minificados.
- El código nunca se ejecuta: solo se lee como texto; el ZIP o el código pegado se borran al terminar el escaneo y los secretos detectados se guardan enmascarados.
- Límites de entrada y cuotas: código pegado de hasta 1024 KB, ZIP y repositorios con límites de tamaño, número de archivos y razón de compresión; máximo 30 escaneos por hora y 2 simultáneos por usuario.
- Propiedad de los datos: existe un único rol de usuario; cada usuario solo ve y modifica sus proyectos, escaneos e issues, y un recurso ajeno responde 404.
- Recursos del plan gratuito: en Render la web y el worker comparten un contenedor de 512 MB y 0,1 CPU, el servicio se duerme a los 15 minutos sin uso y un escaneo largo termina con resultado parcial al agotar su tiempo límite.

## Rangos de calidad

- Seguridad (RNF-01): cumplimiento del nivel 2 de OWASP ASVS 5.0 como referencia: secretos solo por variables de entorno, sesión en el servidor con cookie HttpOnly, Secure y SameSite=Strict, OIDC con PKCE, CSRF, cabeceras CSP y HSTS, recursos ajenos con respuesta 404, límites de ZIP y auditoría de solo inserción.
- Fiabilidad (RNF-02): cola en PostgreSQL con SKIP LOCKED, cada escaneo corre en un proceso aislado con tiempo límite y devuelve un resultado parcial al agotarlo, y el reaper reencola los trabajos de un worker caído (hasta 3 intentos).
- Eficiencia de desempeño (RNF-03): medida en Render free (0,1 CPU y 512 MB): un repositorio de 344 archivos se analiza en unos 2 minutos, el repositorio más grande probado (django, 1143 archivos) tarda 107 s y el pico de memoria es de 353 MB y repetir un escaneo del mismo contenido baja de 125 s a 9 s gracias a la caché.
- Mantenibilidad (RNF-04): arquitectura MVC con capa de servicios, motor separado de la API, migraciones Alembic, cada regla con al menos un verdadero positivo y un verdadero negativo anotados, y análisis continuo con SonarCloud, Semgrep y Snyk.
- Usabilidad (RNF-05): como objetivo de diseño, interfaz en español basada en un sistema de diseño (shadcn/ui), con explicación didáctica de cada hallazgo, filtros guardados en la URL y atajos de teclado; se siguen las pautas WCAG 2.1 AA, sin auditoría formal realizada.
- Portabilidad (RNF-06): imagen Docker multietapa con usuario sin privilegios para la web y el worker; docker compose en local y Render con Neon en la nube, configurados solo por variables de entorno.
- Compatibilidad (RNF-07): informes SARIF 2.1.0 aceptados por GitHub Code Scanning y DefectDojo, API REST descrita en OpenAPI 3 y CLI con códigos de salida para pipelines de CI/CD.

## Precedencia y Prioridad

Se utiliza la metodología MoSCoW para la planificación del desarrollo:

- Must (Obligatorio para la primera entrega):
- Inicio y cierre de sesión con OIDC y sesión segura en el servidor (RF-01 a RF-03).
- Gestión de proyectos y escaneo de código pegado, ZIP y GitHub con seguimiento y cancelación (RF-04 a RF-10).
- Procesamiento en segundo plano con recuperación de escaneos interrumpidos (RF-21, RF-22).
- Hallazgos abiertos del proyecto y resultados con explicación didáctica de cada hallazgo (RF-11 a RF-13).
- Comparación entre escaneos y clasificación persistente de hallazgos (RF-16, RF-17).
- Should (Importante para la operación):
- Exportación de informes SARIF, JSON y HTML y análisis desde la línea de comandos para CI/CD (RF-15, RF-23).
- Catálogo de reglas, con la opción de elegir qué reglas aplicar al escanear (RF-14).
- Comentarios, historial del issue y métricas del proyecto (RF-18, RF-19).
- Retos de corrección con verificación automática de la corrección (RF-26 a RF-28).
- Could (Deseable para fases posteriores):
- Supresión de hallazgos desde el propio código con justificación (RF-20).
- Ampliación del catálogo con reglas Python o YAML y medición con el benchmark (RF-24, RF-25); como mejora posterior, taint sensible a claves de diccionario y sinks de XSS en vistas Flask.

## Otros requerimientos del producto

a. Estándares legales: Cumplimiento de la Ley N.° 29733, Ley de Protección de Datos Personales del Perú, para el correo y el nombre de los usuarios (solo se guardan los datos necesarios para la sesión); licencia MIT del proyecto y respeto de las licencias de terceros (las reglas de Semgrep y el OWASP Benchmark, GPL-3.0, no se copian en el repositorio).

b. Estándares de comunicación: HTTPS con TLS en producción; API REST /api/v1 con JSON documentada en OpenAPI; informes en SARIF 2.1.0 (OASIS), JSON y HTML; autenticación con OpenID Connect y PKCE (RFC 7636).

c. Estándares de cumplimiento de plataforma: navegadores modernos (Google Chrome, Microsoft Edge, Mozilla Firefox); contenedor Docker con Python 3.12 y PostgreSQL 16; despliegue en Render con Neon o con docker compose en cualquier servidor Linux.

d. Estándares de calidad: modelo de calidad ISO/IEC 25010 para los RNF; integración continua en GitHub Actions con pruebas en SQLite y PostgreSQL 16 (más de 210 pruebas de backend y 90 de la web), autoanálisis con SAST Studio y Bandit, y análisis estático externo con SonarCloud, Semgrep y Snyk.

e. Estándares de seguridad: OWASP ASVS 5.0 nivel 2 como objetivo y OWASP Top 10:2021 y CWE como clasificación de los hallazgos; cookies __Host- HttpOnly Secure SameSite=Strict, CSRF, CSP y HSTS, autorización por objeto y secretos solo por variables de entorno.

## CONCLUSIONES

- Valor didáctico definido: SAST Studio no busca detectar más que Bandit, Semgrep, SonarQube o CodeQL, sino enseñar: explica cada hallazgo y cómo corregirlo, y mide el progreso entre escaneos, un hueco que las herramientas gratuitas existentes no cubren.
- Afirmaciones respaldadas por datos: el benchmark reproducible sobre OWASP Benchmark for Python (Youden +20 frente a +17 de Bandit y +4 de Semgrep CE) permite comunicar fortalezas y debilidades sin exagerar.
- Infraestructura y seguridad robustas: el paso de Vercel serverless a un contenedor con worker, PostgreSQL y autenticación OIDC con sesión en el servidor resuelve las fragilidades de la versión 0.1.
- Viabilidad económica: la operación cuesta S/ 0 con los planes gratuitos de Render y Neon, y el diseño autoalojado permite instalarlo en un servidor de la universidad sin costo de licencias.

## RECOMENDACIONES

- Corregir las debilidades medidas: implementar taint sensible a claves de diccionario, modelar sh -c en subprocess y el sink de XSS en vistas Flask, y volver a medir con sast bench.
- Validar con usuarios reales: realizar una prueba piloto con estudiantes de un curso para comprobar que las explicaciones se entienden y ajustar su redacción.
- Vigilar los límites del plan gratuito: si el uso de un curso completo satura los 512 MB y 0,1 CPU de Render, pasar a Render Starter o a un servidor de la universidad.
- Mantener la documentación coherente con el código: actualizar el benchmark, el README y estos documentos en cada versión, y no publicar cifras que no salgan de una medición.

## BIBLIOGRAFÍA

Johnson, B., Song, Y., Murphy-Hill, E., & Bowdidge, R. (2013). Why don't software developers use static analysis tools to find bugs? En Proceedings of the 35th International Conference on Software Engineering (ICSE 2013) (pp. 672–681). IEEE.

Li, K., Chen, S., Fan, L., Feng, R., Liu, H., Liu, C., Liu, Y., & Chen, Y. (2023). Comparison and evaluation on static application security testing (SAST) tools for Java. En Proceedings of the 31st ACM Joint European Software Engineering Conference and Symposium on the Foundations of Software Engineering (ESEC/FSE 2023). ACM.

International Organization for Standardization. (2018). ISO/IEC/IEEE 29148:2018. Systems and software engineering — Life cycle processes — Requirements engineering. ISO.

Congreso de la República del Perú. (2011). Ley N.° 29733: Ley de Protección de Datos Personales. Diario Oficial El Peruano.

IEEE Computer Society. (1998). IEEE Std 830-1998: Recommended Practice for Software Requirements Specifications. IEEE Computer Society.

## WEBGRAFÍA

OWASP Foundation. (2021). OWASP Top 10:2021. Recuperado el 14 de noviembre de 2026, de https://owasp.org/Top10/

MITRE Corporation. (s. f.). CWE – Common Weakness Enumeration. Recuperado el 14 de noviembre de 2026, de https://cwe.mitre.org/

OWASP Foundation. (2025). OWASP Application Security Verification Standard 5.0. Recuperado el 14 de noviembre de 2026, de https://github.com/OWASP/ASVS

OASIS. (2020). SARIF Version 2.1.0. Recuperado el 14 de noviembre de 2026, de https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

IETF. (2015). RFC 7636: Proof Key for Code Exchange by OAuth Public Clients. Recuperado el 14 de noviembre de 2026, de https://www.rfc-editor.org/rfc/rfc7636

OWASP Foundation. (s. f.). OWASP Benchmark for Python. Recuperado el 14 de noviembre de 2026, de https://github.com/OWASP-Benchmark/BenchmarkPython

PyCQA. (s. f.). Bandit documentation. Recuperado el 14 de noviembre de 2026, de https://bandit.readthedocs.io/

Semgrep. (s. f.). Semgrep documentation y planes. Recuperado el 14 de noviembre de 2026, de https://semgrep.dev/docs/ y https://semgrep.dev/pricing

SonarSource. (s. f.). SonarQube Community Build documentation. Recuperado el 14 de noviembre de 2026, de https://docs.sonarsource.com/sonarqube-community-build/

GitHub. (s. f.). CodeQL documentation. Recuperado el 14 de noviembre de 2026, de https://codeql.github.com/docs/

Render. (s. f.). Deploy for Free. Recuperado el 14 de noviembre de 2026, de https://render.com/docs/free

Render. (s. f.). Blueprint YAML Reference. Recuperado el 14 de noviembre de 2026, de https://render.com/docs/blueprint-spec

Neon. (s. f.). Neon plans. Recuperado el 14 de noviembre de 2026, de https://neon.com/docs/introduction/plans
