# Reporte 1 · Pruebas unitarias y de mutación

| | |
|---|---|
| **Proyecto** | SAST Studio |
| **Tipo de prueba** | Unitaria y de mutación |
| **Herramientas** | pytest 9, pytest-cov 7, pytest-html 4, mutmut 3.8 |
| **Automatización** | Job `1 · Unitarias y mutación` de `.github/workflows/pruebas.yml` |
| **Fecha del run** | 16 de noviembre de 2026 |
| **Resultado** | ✅ 123 de 123 pasan · cobertura del motor 85 % · mutación 89,3 % |

## 1. Objetivo

Comprobar que cada pieza del motor de análisis funciona por separado, sin base de datos ni
servidor web, y medir si esas pruebas son lo bastante buenas para detectar errores.

## 2. Qué se prueba

| Archivo de pruebas | Pruebas | Qué verifica |
|---|---:|---|
| `tests/engine/test_engine.py` | 32 | Contrato de las reglas, motor, supresiones (`# nosec`), análisis de taint e informes SARIF y HTML |
| `tests/engine/test_fingerprint.py` | 29 | Huella estable `sastfp/v1`: ventana de líneas, rutas, secretos enmascarados, contador de ocurrencias |
| `tests/unidad/test_archive.py` | 29 | Lectura segura de ZIP: rutas peligrosas, enlaces simbólicos, bombas ZIP y límites exactos |
| `tests/rules/test_annotations.py` | 23 | Cada una de las 22 reglas contra sus casos anotados (`# ruleid:` debe detectarse, `# ok:` no) |
| `tests/engine/test_third_party.py` | 4 | Se omiten dependencias, código minificado y pruebas |
| `tests/test_cli.py` | 3 | Línea de comandos: `scan` a JSON y SARIF, código de salida según el umbral, `rules` y `test-rules` |
| `tests/engine/test_bench.py` | 2 | Benchmark: categorías a partir del CWE y aciertos solo en las líneas anotadas |
| `tests/golden/test_golden.py` | 1 | Los hallazgos sobre `samples/` coinciden con los de referencia guardados |
| **Total** | **123** | |

### Ejemplo: una prueba unitaria

```python
def test_la_huella_sobrevive_a_un_cambio_de_linea():
    antes = ["cur.execute(consulta_insegura)\n"]
    despues = ["# comentario nuevo\n", "\n", "cur.execute(consulta_insegura)\n"]
    h1 = assign_fingerprints([hallazgo(1)], {"app.py": antes})[0].fingerprint
    h2 = assign_fingerprints([hallazgo(3)], {"app.py": despues})[0].fingerprint
    assert h1 == h2
```

## 3. Resultados

| Métrica | Valor |
|---|---|
| Pruebas ejecutadas | 123 |
| Pasan | 123 |
| Fallan | 0 |
| Tiempo | 2,3 s |
| Cobertura de líneas del motor (`sast/`) | 85 % |

## 4. Pruebas de mutación

### Qué son

Una prueba de mutación **cambia el código a propósito** y vuelve a ejecutar las pruebas. Por
ejemplo, cambia `<` por `<=`, `+ 2` por `+ 3` o `True` por `False`. Cada versión alterada es un
*mutante*:

- si alguna prueba falla, el mutante **muere**: las pruebas detectan ese error;
- si todas pasan, el mutante **sobrevive**: ese error pasaría desapercibido.

La **puntuación de mutación** es el porcentaje de mutantes que mueren. Mide la calidad de las
pruebas, no solo cuántas líneas recorren: una línea puede estar cubierta y aun así no tener
ninguna aserción que compruebe su resultado.

### Qué se muta

Se eligieron los tres módulos de lógica pura que más importan para la seguridad y para el
seguimiento de hallazgos (configurado en `[tool.mutmut]` de `pyproject.toml`):

| Módulo | Por qué |
|---|---|
| `sast/engine/fingerprint.py` | Decide si dos hallazgos son «el mismo problema» entre escaneos |
| `sast/engine/context.py` | Decide qué hallazgos se silencian con `# nosec` o `# sast: ignore` |
| `api/services/archive.py` | Decide qué entra de un ZIP subido (defensa contra bombas ZIP y rutas maliciosas) |

### Resultados: antes y después

El primer run dejó una puntuación de **68,0 %**. El reporte de mutantes sobrevivientes señaló
pruebas que faltaban. Se añadieron las de `test_fingerprint.py` y `test_archive.py`, y la
puntuación subió a **89,3 %**:

| Módulo | Mutantes | Antes | Después |
|---|---:|---:|---:|
| `api/services/archive.py` | 229 | 61,0 % | **91,3 %** |
| `sast/engine/context.py` | 112 | 77,7 % | 77,7 % |
| `sast/engine/fingerprint.py` | 136 | 70,9 % | **95,6 %** |
| **Total** | **477** | **68,0 %** | **89,3 %** |

### Qué revelaron los mutantes

Algunos mutantes que sobrevivían y la prueba que los mató:

| Mutante que sobrevivía | Qué significaba | Prueba añadida |
|---|---|---|
| `len(infos) > límite` → `>=` | Nadie comprobaba que un ZIP con exactamente el máximo de entradas se acepta | `test_entradas_totales_justo_en_el_limite_se_aceptan` |
| `len(buf) > max_entry_bytes` → `>=` | No se probaba el tamaño exacto de un archivo | `test_archivo_justo_en_el_tamano_maximo_se_conserva_y_uno_mas_se_omite` |
| `status=422` → `423` | No se comprobaba el código HTTP de cada error | Pruebas de `code`, `status` y `message` de cada error |
| `len(n) > 1` → `len(n) > 2` | No se probaba una unidad de Windows sin ruta (`c:`) | `test_safe_name[c:-None]` |
| `start + 2` → `start + 3` | El tamaño de la ventana de la huella no estaba fijado | `test_ventana_de_tres_lineas_como_maximo` |
| `lstrip("/")` → `rstrip("/")` | No se probaba una ruta con `/` al inicio | `test_normalize_path[/src/app.py-src/app.py]` |
| `counters[key] += 1` → `+= 2` | No se comprobaba el formato exacto de la huella | `test_dos_hallazgos_iguales_tienen_huellas_distintas_y_estables` |

### Mutantes que siguen vivos (51)

El reporte HTML los lista uno por uno con su diferencia. La mayoría son de dos clases:

- **`context.py` (25):** la forma del fragmento de código que se guarda con cada hallazgo
  (`snippet`) y el nombre cualificado de la función. Son textos de presentación; la siguiente
  mejora sería probar el fragmento exacto.
- **Equivalentes:** cambios que no alteran el comportamiento observable, como
  `encode("utf-8")` → `encode("UTF-8")`, que es la misma codificación. Ninguna prueba puede
  matarlos.

## 5. Evidencias

En el artefacto `reportes-de-pruebas` del run:

- `1-unitarias/unitarias.html`: el resultado de cada prueba;
- `1-unitarias/cobertura/index.html`: la cobertura línea a línea;
- `1-unitarias/mutacion.html`: la puntuación por módulo y cada mutante sobreviviente con su diferencia.

## 6. Conclusiones

- Las 123 pruebas unitarias pasan en unos 2 segundos, así que se pueden ejecutar en cada cambio.
- La mutación demostró que **ejecutar el código no es lo mismo que comprobarlo**: `archive.py` ya
  se ejercitaba en las pruebas del worker, pero solo morían el 61 % de sus mutantes. Faltaban
  pruebas de los límites exactos y de los códigos de error.
- Con 58 pruebas nuevas guiadas por el reporte, la puntuación pasó del 68,0 % al 89,3 %.
