# Línea base del motor

Generado con `python scripts/baseline.py`. Corpus: `samples/`, `api/`, `sast/` y `tests/rules/cases/`.

| Métrica | Valor |
|---|---|
| Archivos analizados | 73 |
| Líneas de código | 5257 |
| Hallazgos totales | 88 |
| Tiempo (mediana de 3) | 0.25 s |
| Tiempo por KLOC | 47.5 ms |
| Hallazgos del auto-escaneo de `api/` | 5 |
| Hallazgos duplicados (mismo ID estable y línea) | 0 |
| Anotaciones `ruleid` / `ok` | 37 / 27 |
| Defectos conocidos (`todoruleid` + `todook`) | 0 |

## Defectos conocidos aún abiertos

- Ninguno.

## Defectos conocidos que el motor actual ya corrige

(Cuando aparecen aquí, la anotación `todo*` debe pasar a `ruleid` / `ok`.)

- Ninguno.

Pasadas completas de taint por archivo Python: **1** (motor heredado: 5).

Comparación de velocidad en el mismo corpus (medida en F1, antes de borrar el motor heredado): heredado 70,1 ms/KLOC; nuevo 34,2 ms/KLOC (unas 2 veces más rápido, aunque ahora hace taint entre funciones). El objetivo de 1/3 (23 ms/KLOC) no se alcanzó; se revisa en F8.
