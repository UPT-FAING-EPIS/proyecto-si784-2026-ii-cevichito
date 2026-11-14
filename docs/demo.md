# Guion de demo (5 minutos)

Para enseñar SAST Studio a un revisor. Cada paso responde a una de las cuatro observaciones de
la revisión: diferenciación, arquitectura, reglas y base de datos.

## Antes de empezar (5 min de preparación)

- La app abierta y con la sesión iniciada: en local `docker compose up -d` →
  <http://localhost:8080>, o la URL de Render (despiértala unos minutos antes: tarda 1–2 min).
- Un proyecto vacío llamado `demo`.
- Una terminal con el repositorio abierto.
- Ten a mano dos versiones de un archivo: `samples/vulnerable_sample.py` y una copia en la que
  hayas corregido la inyección SQL (consulta con `?` y parámetros).

## 1. Un hallazgo explicado en español (1 min) · *diferenciación*

1. «Nuevo escaneo» → **Repositorio de GitHub** → `stamparm/DSVW` → Lanzar.
2. Mientras termina (~10 s en local): «Se analiza en un proceso aparte; la web no se bloquea».
3. Abre una **Inyección SQL**. Enseña:
   - el **recorrido del dato**, desde la entrada del usuario hasta la consulta;
   - «Qué ocurre» y «Cómo corregirlo», con el ejemplo vulnerable y el corregido;
   - el CWE y el OWASP enlazados.

> Frase: «Bandit o Semgrep dicen *B608: possible SQL injection*. Aquí el estudiante ve por dónde
> entra el dato y cómo se corrige, en su idioma».

## 2. El progreso entre escaneos (1,5 min) · *diferenciación + base de datos*

1. En el proyecto `demo`, pega `samples/vulnerable_sample.py` y escanéalo.
2. Abre un hallazgo de secreto → «Revisar y anotar» → **Falso positivo** con una justificación.
3. Pega la versión corregida y vuelve a escanear.
4. Pulsa **Comparar con el anterior**: nuevos, corregidos y reabiertos.
5. Señala que el falso positivo **sigue marcado** en el escaneo nuevo.

> Frase: «Cada problema tiene una huella estable (`sastfp/v1`) que sobrevive a los cambios de
> línea. El ciclo de vida lo decide el sistema; la revisión, las personas. Por eso el falso
> positivo no se pierde al volver a escanear».

## 3. Una regla por dentro (1 min) · *reglas*

En la terminal:

```bash
python -m sast rules | head
python -m sast test-rules tests/rules/cases
```

Abre `tests/rules/cases/py-sql-injection.py` y enseña:

- `# ruleid: py/sql-injection` encima de una línea que **debe** detectarse;
- `# ok: py/sql-injection` encima de una que **no** (consulta parametrizada);
- el caso real de DVPWA, añadido como regresión tras escanear el repositorio de verdad.

> Frase: «Cada regla tiene un contrato (id estable, severidad, CWE, explicación) y casos de prueba
> en el formato de Semgrep. Si alguien rompe una regla, la CI falla».

## 4. La arquitectura aguanta fallos (1 min) · *arquitectura*

Lanza un escaneo grande (`sqlalchemy/sqlalchemy`) y, mientras corre:

```bash
docker kill sast-studio-worker-1
docker compose up -d worker
```

En la web, el escaneo queda «En curso». A los 2 minutos el **reaper** lo devuelve a la cola y
termina solo. Si no quieres esperar en directo, enséñalo con el registro de la prueba en
`docs/ESTADO.md`.

> Frase: «La API y el worker son procesos separados que se coordinan con una cola en PostgreSQL
> (`SKIP LOCKED`). Si el worker muere, el trabajo no se pierde».

## 5. Los números, sin maquillar (30 s) · *diferenciación*

Abre [`docs/benchmark.md`](benchmark.md):

- En OWASP Benchmark for Python, media de Youden +20, frente a +17 de Bandit y +4 de Semgrep CE.
- Inyección SQL: +100.
- Las debilidades, con su causa: comandos, XSS y path traversal.

> Frase: «No decimos que detecte más que todo. Decimos lo que medimos, y dónde falla».

## Preguntas probables

| Pregunta | Respuesta corta |
|---|---|
| ¿Por qué no usar Semgrep y ya? | Semgrep detecta; SAST Studio enseña y mide el progreso. Sus reglas públicas además tienen una licencia que limita su uso como servicio. |
| ¿Análisis entre archivos? | No: es entre funciones, pero dentro de cada archivo. Está documentado como límite. |
| ¿Y si se cae el servidor a mitad de un escaneo? | El reaper lo reencola a los 2 min (paso 4). |
| ¿Dónde está el código del usuario? | Solo en el servidor propio. El ZIP o el código pegado se borra al terminar el escaneo; de cada hallazgo se guardan unas líneas de contexto (con los secretos enmascarados). |
| ¿Cómo se añade una regla? | Una clase de Python o un YAML, más su archivo de casos anotados. |
