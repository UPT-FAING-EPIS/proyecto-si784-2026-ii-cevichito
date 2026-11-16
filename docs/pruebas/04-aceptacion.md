# Reporte 4 · Pruebas de aceptación

| | |
|---|---|
| **Proyecto** | SAST Studio |
| **Tipo de prueba** | Aceptación de usuario (BDD) |
| **Herramientas** | Gherkin en español, pytest-bdd 9, pytest-html 4 |
| **Automatización** | Job `4 · Aceptación (Gherkin)` de `.github/workflows/pruebas.yml` |
| **Fecha del run** | 16 de noviembre de 2026 |
| **Resultado** | ✅ 17 de 17 escenarios pasan |

## 1. Objetivo

Comprobar que SAST Studio cumple **lo que el usuario necesita**, escrito en su propio lenguaje.
Cada escenario es un criterio de aceptación de un caso de uso del FD03, redactado en Gherkin
(«Dado… Cuando… Entonces…») para que lo pueda leer y validar alguien que no programa: un docente,
un estudiante o el cliente.

## 2. Cómo funcionan

- Los escenarios están en `tests/aceptacion/features/*.feature`, en español (`# language: es`).
- Cada frase se conecta con un paso en Python (`tests/aceptacion/test_aceptacion.py`) que habla
  con SAST Studio por HTTP, como la web.
- Se ejecutan contra el **servidor real**: web, worker y base de datos.
- Las etiquetas `@CUS-xx` enlazan cada característica con su caso de uso. Por ejemplo,
  `pytest -m CUS-27` ejecuta solo los escenarios de «Resolver reto en el editor».

### Ejemplo

```gherkin
# language: es
@CUS-26 @CUS-27 @CUS-28
Característica: Retos de corrección
  Como estudiante
  Quiero corregir código vulnerable preparado
  Para practicar y que el sistema compruebe si lo corregí de verdad

  Escenario: Silenciar el aviso no cuenta como corregir
    Dado que soy un estudiante con sesión iniciada
    Cuando envío el código de partida del reto "01-login-sql" silenciado con "# nosec"
    Entonces el veredicto es "silenciado"
```

## 3. Escenarios

| Característica | Casos de uso | Escenario | Resultado |
|---|---|---|---|
| Analizar código y entender el hallazgo | CUS-07, CUS-13 | Se detecta una inyección SQL y se explica (severidad crítica, explicación, corrección, ejemplos y CWE-89) | ✅ |
| | | El código seguro no tiene hallazgos graves | ✅ |
| Medir el progreso entre escaneos | CUS-16, CUS-17 | Corregir el fallo lo marca como corregido en la comparación | ✅ |
| | | Un falso positivo sigue marcado al volver a escanear, aunque el código se haya desplazado una línea | ✅ |
| Retos de corrección | CUS-26, CUS-27, CUS-28 | Cada reto se supera con una corrección real: **8 escenarios**, uno por reto (el código de partida da «sigue» y la solución da «superado») | ✅ ×8 |
| | | Silenciar el aviso con `# nosec` no cuenta como corregir | ✅ |
| | | Borrar el código no cuenta como corregir (`missing_functions`) | ✅ |
| | | Un código con errores de sintaxis se rechaza sin analizarlo (`syntax_error`) | ✅ |
| Cada usuario solo ve lo suyo | CUS-04, CUS-05 | Otro estudiante no puede abrir mi proyecto (404) ni lo ve en su lista | ✅ |
| | | Sin iniciar sesión no se accede a la API (401) | ✅ |

Los 8 retos se cubren con un **esquema del escenario** (*Esquema del escenario* + *Ejemplos*):
un único texto que se ejecuta con cada fila de la tabla.

## 4. Resultados

| Escenarios | Pasan | Fallan | Tiempo |
|---:|---:|---:|---:|
| 17 | 17 | 0 | 42,0 s |

## 5. Evidencias

En el artefacto `reportes-de-pruebas` del run:

- `4-aceptacion/aceptacion.html`: cada escenario con su resultado;
- `4-aceptacion/cucumber.json`: los resultados en formato Cucumber, que otras herramientas de
  BDD pueden convertir en informes.

En el log del job se ve cada escenario paso a paso, en español, gracias a
`--gherkin-terminal-reporter`.

## 6. Conclusiones

- Los criterios de aceptación de los casos de uso principales se cumplen: analizar y entender
  un hallazgo, medir el progreso y resolver retos.
- La propuesta de valor, **enseñar a corregir**, queda comprobada de forma automática: cada
  reto solo se supera con una corrección real, y ni silenciar el aviso ni borrar el código
  cuentan como corregir.
- Al estar en español y en lenguaje del usuario, los escenarios sirven también como
  documentación viva de lo que hace el sistema.
