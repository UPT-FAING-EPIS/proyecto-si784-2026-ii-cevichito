# Benchmark: SAST Studio frente a Bandit y Semgrep CE

Medido el 14 de noviembre de 2026 con `sast bench` ([`sast/bench/`](../sast/bench/__init__.py)).
El objetivo no es «ganar»: es que el proyecto no afirme nada que no haya medido.

## Resumen

- En el corpus **neutral** (OWASP Benchmark for Python, 1230 casos), SAST Studio obtiene la
  media de Youden más alta de las tres herramientas: **+20** frente a +17 de Bandit y +4 de
  Semgrep CE con reglas públicas. En las 8 categorías para las que tiene reglas: **+35**, +31 y +8.
- Destaca en **inyección SQL** (+100: detecta todos los casos vulnerables y ningún seguro), donde
  Bandit marca también todos los seguros (+0).
- Tiene **tres debilidades claras**, todas con causa conocida (ver «Qué falla y por qué»):
  inyección de comandos (−46), XSS (−7) y path traversal (+4).
- Ninguna herramienta cubre 6 de las 14 categorías de OWASP (LDAP, XPath, XXE, redirecciones,
  cookies y frontera de confianza), salvo Bandit en XXE, que marca todos los casos por igual (+0).
- En el corpus **propio** SAST Studio saca 100 % de precisión y de recall. **Ese resultado no
  prueba nada por sí solo**: los casos se escribieron junto con sus reglas. Se publica para que
  cualquiera pueda ejecutar las otras herramientas sobre los mismos archivos.

## Método

**Herramientas y versiones**

| Herramienta | Versión | Configuración |
|---|---|---|
| SAST Studio | 0.2.0 (commit de este documento) | Todas las reglas, confianza mínima baja |
| Bandit | 1.9.4 | `bandit -r` con la configuración por defecto |
| Semgrep CE | 1.100.0 (imagen `semgrep/semgrep:1.100.0`) | Reglas públicas `p/python` y `p/secrets` |

Semgrep se usa solo como competidor en el benchmark, no se incrusta en el producto. Sus reglas
públicas tienen licencia restrictiva y no se redistribuyen. Semgrep Pro (de pago) incluye
análisis entre archivos y podría puntuar más; no se evaluó.

**Comparación por categoría.** Cada herramienta nombra sus reglas a su manera, así que cada
hallazgo se reduce a una categoría (inyección SQL, comandos, criptografía débil…):

- SAST Studio y Semgrep, por el CWE de la regla.
- Bandit, por su ID de prueba (por ejemplo B608 → inyección SQL), porque sus CWE son imprecisos:
  B307 (`eval`) declara CWE-78, que es inyección de comandos.

**OWASP Benchmark for Python** ([repositorio](https://github.com/OWASP-Benchmark/BenchmarkPython),
commit `f129148`, GPL-3.0; se descarga, no se copia aquí). Cada archivo `BenchmarkTestNNNNN.py` es
vulnerable o no, para una categoría. Una herramienta «marca» un caso si informa esa categoría en
ese archivo. La puntuación es la de OWASP: **Youden = TPR − FPR**.

- 0 significa que la herramienta no distingue los casos vulnerables de los seguros: no marca
  ninguno, o los marca todos.
- +100 es perfecto. Un valor negativo marca más casos seguros que vulnerables.

**Corpus anotado propio** (`tests/rules/cases`, solo Python). Línea a línea: `# ruleid:` es
vulnerable y `# ok:` es seguro. Los falsos negativos conocidos (`todoruleid`) cuentan como
vulnerables para todas las herramientas, también para SAST Studio.

**Repositorios reales** (sin verdad por línea): solo describe qué categorías encuentra cada
herramienta y cuánto tarda.

| Repositorio | Commit |
|---|---|
| [fportantier/vulpy](https://github.com/fportantier/vulpy) (`bad/` y `good/`) | `5249cc8` |
| [stamparm/DSVW](https://github.com/stamparm/DSVW) | `9ca3c9a` |
| [anxolerd/dvpwa](https://github.com/anxolerd/dvpwa) (`sqli/`) | `4a8f4a4` |

Los tiempos son de una sola ejecución en un portátil con Windows. Semgrep corre en Docker y su
tiempo incluye el arranque del contenedor y la descarga de reglas, así que no son comparables
como medida de rendimiento.

## 1. OWASP Benchmark for Python

1230 casos de prueba (452 vulnerables de verdad), 14 categorías. Celda: **Youden** (TPR / FPR),
en puntos porcentuales.

| Categoría | SAST Studio | Bandit | Semgrep CE |
|---|---:|---:|---:|
| Aleatoriedad insegura | **+59** (59 / 0) | **+78** (78 / 0) | **+0** (0 / 0) |
| Cookie sin Secure | **+0** (0 / 0) | **+0** (0 / 0) | **+0** (0 / 0) |
| Criptografía débil | **+100** (100 / 0) | **+100** (100 / 0) | **+76** (76 / 0) |
| Deserialización insegura | **+67** (100 / 33) | **+67** (100 / 33) | **+31** (44 / 14) |
| Ejecución de código (eval/exec) | **+0** (100 / 100) | **+0** (100 / 100) | **+0** (0 / 0) |
| Inyección LDAP | **+0** (0 / 0) | **+0** (0 / 0) | **+0** (0 / 0) |
| Inyección SQL | **+100** (100 / 0) | **+0** (100 / 100) | **+0** (0 / 0) |
| Inyección XPath | **+0** (0 / 0) | **+0** (0 / 0) | **+0** (0 / 0) |
| Inyección de comandos | **−46** (54 / 100) | **+0** (100 / 100) | **−46** (54 / 100) |
| Path traversal | **+4** (22 / 17) | **+0** (0 / 0) | **+1** (3 / 2) |
| Redirección abierta | **+0** (0 / 0) | **+0** (0 / 0) | **+0** (0 / 0) |
| Violación de frontera de confianza | **+0** (0 / 0) | **+0** (0 / 0) | **+0** (0 / 0) |
| XSS | **−7** (0 / 7) | **+0** (0 / 0) | **+0** (0 / 0) |
| XXE | **+0** (0 / 0) | **+0** (100 / 100) | **+0** (0 / 0) |
| **Media, las 14 categorías** | **+20** | **+17** | **+4** |
| **Media, las 8 que cubre SAST Studio** | **+35** | **+31** | **+8** |

### Qué falla y por qué

| Categoría | Síntoma | Causa en el motor | Arreglo propuesto |
|---|---|---|---|
| Inyección de comandos | Marca el 100 % de los casos seguros | El taint no distingue las claves de un diccionario: si `map['keyB']` lleva datos del usuario, `map['keyA']` (constante) también se considera contaminado. | Taint sensible a claves constantes de `dict`. |
| Inyección de comandos | Se le escapa el 46 % de los vulnerables | `subprocess.run([...])` solo es sink con `shell=True`; una lista `["sh", "-c", f"echo {x}"]` pasa. | Modelar `sh/bash -c` como primer argumento del vector. |
| XSS | No detecta ningún caso | Devolver un f-string con datos del usuario desde una vista de Flask no está modelado como sink. | Sink «valor de retorno de una vista Flask con texto HTML». |
| Path traversal | Casi azar (22 % / 17 %) | Mezcla de los dos problemas anteriores: contenedores y sinks de `os.path`/`open` indirectos. | Tras arreglar el taint de diccionarios, volver a medir. |
| `eval`/`exec` | +0 en las tres | Las tres herramientas marcan cualquier `eval`, venga o no de datos del usuario. | Variante taint de `py/dangerous-function`. |

## 2. Corpus anotado propio

> **Sesgo:** estos casos se escribieron junto con las reglas de SAST Studio. Su 100 % muestra que
> las reglas hacen lo que dicen, no que detecten más que las demás herramientas.

31 líneas vulnerables y 22 seguras anotadas.

| Herramienta | Aciertos | Falsos positivos | No detectados | Precisión | Recall |
|---|---:|---:|---:|---:|---:|
| SAST Studio | 31 | 0 | 0 | 100 % | 100 % |
| Bandit | 19 | 4 | 12 | 83 % | 61 % |
| Semgrep CE | 14 | 2 | 17 | 88 % | 45 % |

| Categoría (aciertos / vulnerables, falsos positivos) | SAST Studio | Bandit | Semgrep CE |
|---|---:|---:|---:|
| Aleatoriedad insegura | 1/1 | 1/1 | 0/1 |
| Configuración insegura | 3/3 | 3/3 | 2/3 |
| Criptografía débil | 8/8 | 6/8 | 6/8 |
| Deserialización insegura | 2/2 | 2/2 | 0/2 |
| Ejecución de código (eval/exec) | 2/2 | 2/2 | 0/2 |
| Inyección SQL | 4/4 | 2/4 (1) | 1/4 |
| Inyección de comandos | 3/3 | 3/3 (2) | 2/3 (1) |
| JWT sin verificar | 1/1 | 0/1 | 0/1 |
| Path traversal | 1/1 | 0/1 | 1/1 |
| SSRF | 1/1 | 0/1 | 1/1 |
| Secretos en el código | 4/4 | 0/4 (1) | 0/4 |
| XSS | 1/1 | 0/1 | 1/1 (1) |

## 3. Repositorios reales

Número de hallazgos por categoría (sin verdad por línea: más no significa mejor).

| | vulpy `bad/` (SAST / Bandit / Semgrep) | vulpy `good/` | DSVW | DVPWA `sqli/` |
|---|---:|---:|---:|---:|
| Inyección SQL | 4 / 5 / 0 | 1 / 1 / 0 | 3 / 3 / 0 | 1 / 1 / 0 |
| Inyección de comandos | 0 / 2 / 1 | — | 1 / 6 / 1 | — |
| Deserialización insegura | — | — | 1 / 3 / 0 | — |
| Ejecución de código | — | — | 1 / 1 / 0 | — |
| Aleatoriedad insegura | 1 / 1 / 0 | — | 1 / 1 / 0 | — |
| Criptografía débil | — | — | — | 1 / 1 / 2 |
| Secretos en el código | 0 / 2 / 0 | 2 / 3 / 0 | — | — |
| Configuración insegura | 2 / 2 / 2 | 2 / 2 / 2 | — | — |
| SSRF | — | — | 0 / 1 / 0 | — |
| XXE | — | — | 0 / 4 / 0 | — |
| **Total** | **7 / 12 / 3** | **5 / 6 / 2** | **7 / 19 / 1** | **2 / 2 / 2** |

Lectura:

- **vulpy:** de la versión vulnerable a la corregida, SAST Studio baja de 4 a 1 inyecciones SQL.
  Las 2 de configuración siguen en ambas versiones en las tres herramientas: `good/` no corrige
  todo.
- **DSVW:** Bandit informa más (19), sobre todo comandos y XXE. Parte son avisos por el mero uso
  de `subprocess` o de `xml`, sin comprobar el origen del dato. SAST Studio no tiene reglas de XXE.
- **DVPWA:** las tres coinciden en el MD5. La inyección SQL de `student.py` la ven SAST Studio y
  Bandit; Semgrep CE no.

## Qué se puede afirmar (y qué no)

Se puede:

- «En OWASP Benchmark for Python, SAST Studio obtiene una media de Youden de +20, por encima de
  Bandit 1.9.4 (+17) y de Semgrep CE 1.100.0 con reglas públicas (+4).»
- «Detecta la inyección SQL de OWASP Benchmark sin falsos positivos (+100).»

No se puede:

- Decir que «detecta más que Semgrep» en general: Semgrep Pro y CodeQL no se evaluaron, y el
  análisis entre archivos de SAST Studio no existe.
- Usar el 100 % del corpus propio como prueba de calidad.
- Comparar tiempos con Semgrep (incluyen Docker).

## Cómo reproducirlo

```bash
pip install "bandit==1.9.4"
docker pull semgrep/semgrep:1.100.0
# Descarga los corpus (zipball de GitHub) en una carpeta fuera del repo, por ejemplo ../corpus
python -m sast bench \
  --owasp ../corpus/BenchmarkPython \
  --real "vulpy (bad)=../corpus/vulpy/bad" --real "vulpy (good)=../corpus/vulpy/good" \
  --real "DSVW=../corpus/DSVW" --real "DVPWA=../corpus/dvpwa/sqli" \
  -o resultados.md
```
