# Línea base del motor

Generado con `python scripts/baseline.py`. Corpus: `samples/`, `api/`, `sast/` y `tests/rules/cases/`.

| Métrica | Valor |
|---|---|
| Archivos analizados | 63 |
| Líneas de código | 5682 |
| Hallazgos totales | 98 |
| Tiempo (mediana de 3) | 0.40 s |
| Tiempo por KLOC | 70.1 ms |
| Hallazgos del auto-escaneo de `api/` | 0 |
| Hallazgos duplicados (mismo ID estable y línea) | 9 |
| Anotaciones `ruleid` / `ok` | 21 / 21 |
| Defectos conocidos (`todoruleid` + `todook`) | 12 |

## Defectos conocidos aún abiertos

- generic-hardcoded-secret.py:14 falta `generic/hardcoded-secret`
- generic-hardcoded-secret.py:23 falta `generic/hardcoded-secret`
- multi-sql-injection.php:5 falta `multi/sql-injection`
- py-command-injection.py:22 falta `py/command-injection`
- py-insecure-password-hash.py:7 falta `py/insecure-password-hash`
- py-path-traversal.py:9 falta `py/path-traversal`
- py-sql-injection.py:12 falta `py/sql-injection`
- py-sql-injection.py:30 falta `py/sql-injection`
- py-weak-cipher.py:8 falta `py/weak-cipher`
- py-weak-cipher.py:11 falta `py/weak-cipher`
- py-weak-hash.py:14 sobra `py/weak-hash`
- py-xss.py:9 falta `py/xss`

## Defectos conocidos que el motor actual ya corrige

(Cuando aparecen aquí, la anotación `todo*` debe pasar a `ruleid` / `ok`.)

- Ninguno.

Pasadas completas de taint por archivo (motor heredado): **5** (una por cada regla de inyección).
