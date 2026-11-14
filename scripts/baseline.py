"""Mide la línea base del motor: hallazgos, tiempo por KLOC y defectos conocidos.

Uso:  python scripts/baseline.py > docs/baseline.md

Funciona con el motor heredado (F0) y con el nuevo (desde F1), porque usa el
adaptador del arnés de anotaciones para obtener los hallazgos de cada caso.
"""

from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.rules.annotations import case_files, parse_expectations  # noqa: E402
from tests.rules.engine_adapter import findings_for  # noqa: E402

CORPUS = [ROOT / "samples", ROOT / "api", ROOT / "sast", ROOT / "tests" / "rules" / "cases"]
CODE_EXT = {".py", ".js", ".ts", ".tsx", ".php"}


def corpus_files() -> list[Path]:
    files: list[Path] = []
    for base in CORPUS:
        files.extend(p for p in base.rglob("*") if p.suffix in CODE_EXT and "__pycache__" not in p.parts)
    return sorted(files)


def measure() -> dict:
    files = corpus_files()
    loc = sum(len(p.read_text(encoding="utf-8", errors="replace").splitlines()) for p in files)
    runs = []
    total = 0
    for _ in range(3):
        t0 = time.perf_counter()
        total = sum(len(findings_for(p)) for p in files)
        runs.append(time.perf_counter() - t0)
    seconds = statistics.median(runs)
    return {"files": len(files), "loc": loc, "findings": total, "seconds": seconds,
            "ms_per_kloc": seconds * 1000 / (loc / 1000)}


def self_scan_api() -> int:
    return sum(len(findings_for(p)) for p in (ROOT / "api").rglob("*.py"))


def annotation_status() -> dict:
    stats = {"ruleid": 0, "ok": 0, "todoruleid": 0, "todook": 0, "todo_fixed": [], "todo_open": []}
    for case in case_files():
        exp = parse_expectations(case)
        got = set(findings_for(case))
        stats["ruleid"] += len(exp.must)
        stats["ok"] += len(exp.must_not)
        stats["todoruleid"] += len(exp.todo_must)
        stats["todook"] += len(exp.todo_must_not)
        for rid, line in sorted(exp.todo_must):
            bucket = "todo_fixed" if (rid, line) in got else "todo_open"
            stats[bucket].append(f"{case.name}:{line} falta `{rid}`")
        for rid, line in sorted(exp.todo_must_not):
            bucket = "todo_fixed" if (rid, line) not in got else "todo_open"
            stats[bucket].append(f"{case.name}:{line} sobra `{rid}`")
    return stats


def duplicates() -> int:
    """Ubicaciones (archivo, línea) con más de un hallazgo del mismo ID estable."""
    dup = 0
    for p in corpus_files():
        pairs = findings_for(p)
        dup += len(pairs) - len(set(pairs))
    return dup


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    m = measure()
    a = annotation_status()
    print("# Línea base del motor\n")
    print("Generado con `python scripts/baseline.py`. Corpus: `samples/`, `api/`, `sast/` y `tests/rules/cases/`.\n")
    print("| Métrica | Valor |\n|---|---|")
    print(f"| Archivos analizados | {m['files']} |")
    print(f"| Líneas de código | {m['loc']} |")
    print(f"| Hallazgos totales | {m['findings']} |")
    print(f"| Tiempo (mediana de 3) | {m['seconds']:.2f} s |")
    print(f"| Tiempo por KLOC | {m['ms_per_kloc']:.1f} ms |")
    print(f"| Hallazgos del auto-escaneo de `api/` | {self_scan_api()} |")
    print(f"| Hallazgos duplicados (mismo ID estable y línea) | {duplicates()} |")
    print(f"| Anotaciones `ruleid` / `ok` | {a['ruleid']} / {a['ok']} |")
    print(f"| Defectos conocidos (`todoruleid` + `todook`) | {a['todoruleid'] + a['todook']} |")
    print("\n## Defectos conocidos aún abiertos\n")
    for item in a["todo_open"] or ["Ninguno."]:
        print(f"- {item}")
    print("\n## Defectos conocidos que el motor actual ya corrige\n")
    print("(Cuando aparecen aquí, la anotación `todo*` debe pasar a `ruleid` / `ok`.)\n")
    for item in a["todo_fixed"] or ["Ninguno."]:
        print(f"- {item}")


if __name__ == "__main__":
    main()
