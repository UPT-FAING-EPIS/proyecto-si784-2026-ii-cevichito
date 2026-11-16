# Reportes de pruebas automatizadas

SAST Studio automatiza cuatro tipos de prueba. Cada uno tiene su informe en esta carpeta y se
ejecuta solo en cada push con el workflow
[`.github/workflows/pruebas.yml`](../../.github/workflows/pruebas.yml).

| # | Informe | Herramientas | Pruebas | Resultado |
|---|---|---|---:|---|
| 1 | [Pruebas unitarias y de mutación](01-unitarias-y-mutacion.md) | pytest, pytest-cov, mutmut | 123 | 123 pasan · cobertura 85 % · mutación **89,3 %** |
| 2 | [Pruebas de integración y de sistema](02-integracion-y-sistema.md) | pytest, PostgreSQL 16, requests | 180 + 7 | 187 pasan |
| 3 | [Pruebas de interfaz de usuario](03-interfaz-de-usuario.md) | Playwright (Chromium), pytest-playwright | 7 | 7 pasan, con capturas |
| 4 | [Pruebas de aceptación](04-aceptacion.md) | Gherkin en español, pytest-bdd | 17 escenarios | 17 pasan |

**Total: 334 pruebas automatizadas, todas en verde.** Cifras del run del 16 de noviembre de 2026.

## Dónde ver los reportes generados

Cada ejecución del workflow deja el artefacto **`reportes-de-pruebas`**:

1. Ir a **Actions → Pruebas automatizadas y reportes**.
2. Abrir el último run.
3. Descargar el artefacto `reportes-de-pruebas` y abrir `index.html`.

Contenido del artefacto:

```text
reportes-de-pruebas/
├── index.html                      índice con el resumen de todo
├── 1-unitarias/
│   ├── unitarias.html              reporte de pytest
│   ├── cobertura/index.html        cobertura línea a línea
│   └── mutacion.html               puntuación y mutantes sobrevivientes
├── 2-integracion-sistema/
│   ├── integracion.html
│   └── sistema.html
├── 3-interfaz/interfaz.html        con una captura de pantalla por prueba
└── 4-aceptacion/
    ├── aceptacion.html
    └── cucumber.json               formato Cucumber, para otras herramientas
```

El resumen también aparece en la página del run, en la pestaña **Summary**.

## Cómo ejecutarlas en local

```bash
pip install -r requirements.lock -r requirements-pruebas.txt
pip install -e . --no-deps
```

```bash
python -m pytest tests/engine tests/unidad tests/rules tests/golden tests/test_cli.py   # 1. unitarias
```

```bash
python -m pytest tests/api                       # 2. integración (SQLite; con TEST_DATABASE_URL, PostgreSQL)
```

```bash
python -m pytest -m sistema tests/e2e            # 2. sistema
```

```bash
cd web && npm ci && npm run build && cd .. && python -m playwright install chromium
```

```bash
python -m pytest -m ui tests/e2e                 # 3. interfaz
```

```bash
python -m pytest -m aceptacion tests/aceptacion  # 4. aceptación
```

Las pruebas de mutación necesitan Linux o WSL, porque mutmut no funciona en Windows:

```bash
mutmut run && python scripts/reporte_mutacion.py --html mutacion.html --md mutacion.md
```

Un `python -m pytest` sin opciones ejecuta solo las pruebas rápidas (unitarias e integración).
Las de sistema, interfaz y aceptación arrancan el servidor completo y se piden con `-m`.

## Pirámide de pruebas

```text
              ▲   4. Aceptación (17)        ¿hace lo que el usuario necesita?
             ▲▲▲  3. Interfaz (7)           ¿funciona en un navegador real?
           ▲▲▲▲▲  2. Sistema (7)            ¿funciona todo junto, como en producción?
        ▲▲▲▲▲▲▲▲  2. Integración (180)      ¿la API y la base de datos encajan?
  ▲▲▲▲▲▲▲▲▲▲▲▲▲▲  1. Unitarias (123)        ¿cada pieza hace lo correcto?
```

Hay muchas pruebas rápidas en la base y pocas lentas arriba: las unitarias tardan 2 segundos y
la aceptación, unos 45.
