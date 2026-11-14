"""Genera docs/rules/<id>.md a partir de los metadatos de cada regla (fuente única).

Uso:  python scripts/gen_rule_docs.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sast.rules.registry import default_ruleset  # noqa: E402

OUT = ROOT / "docs" / "rules"


def render(m) -> str:
    heur = "\n> Regla heurística (expresiones regulares): no analiza el flujo de datos.\n" if m.engine == "heuristic" else ""
    refs = "\n".join(f"- <{r}>" for r in m.references) or "- (sin referencias)"
    return f"""# {m.name}

`{m.id}` · severidad **{m.severity.label_es}** · confianza {m.confidence.label} · {", ".join(m.cwe)} · OWASP {", ".join(m.owasp)}
{heur}
## Qué es y por qué es peligroso

{m.explanation}

## Cómo corregirlo

{m.remediation}

## Ejemplo vulnerable

```
{m.example_bad}
```

## Ejemplo corregido

```
{m.example_good}
```

## Referencias

{refs}
"""


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    index = ["# Catálogo de reglas\n", "| ID | Nombre | Severidad | Motor |", "|---|---|---|---|"]
    for m in default_ruleset().metas():
        name = m.id.replace("/", "-") + ".md"
        (OUT / name).write_text(render(m), encoding="utf-8")
        index.append(f"| [`{m.id}`]({name}) | {m.name} | {m.severity.label_es} | {m.engine} |")
    (OUT / "README.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    print(f"{len(index) - 3} reglas documentadas en {OUT}")


if __name__ == "__main__":
    main()
