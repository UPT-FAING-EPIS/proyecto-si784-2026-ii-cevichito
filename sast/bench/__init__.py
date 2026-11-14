"""Benchmark reproducible: SAST Studio frente a Bandit y Semgrep CE sobre los mismos archivos.

Dos tipos de corpus:

* **Anotado** (verdad conocida): los casos `# ruleid:` / `# ok:` de `tests/rules/cases`. Cada
  anotación se traduce a una *categoría* de vulnerabilidad. Una herramienta acierta si informa
  esa categoría en esa línea; se equivoca si la informa en una línea `ok`. Los falsos negativos
  conocidos (`todoruleid`) cuentan como vulnerables para todas, también para SAST Studio.
* **Real** (sin verdad por línea): repositorios vulnerables públicos. Solo se describe qué
  categorías encuentra cada herramienta y cuánto tarda.

Las herramientas se comparan por categoría y no por identificador de regla, porque cada una
nombra sus reglas a su manera. Bandit se mapea por su ID de prueba: sus CWE son imprecisos
(p. ej. B307 `eval` aparece como CWE-78).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..testing import case_files, parse_expectations

# --- Categorías ---------------------------------------------------------------------------------

CATEGORY_LABEL = {
    "sqli": "Inyección SQL", "cmdi": "Inyección de comandos", "code": "Ejecución de código (eval/exec)",
    "deser": "Deserialización insegura", "path": "Path traversal", "xss": "XSS", "ssrf": "SSRF",
    "crypto": "Criptografía débil", "random": "Aleatoriedad insegura", "secret": "Secretos en el código",
    "jwt": "JWT sin verificar", "config": "Configuración insegura", "ldapi": "Inyección LDAP",
    "xpathi": "Inyección XPath", "xxe": "XXE", "redirect": "Redirección abierta",
    "securecookie": "Cookie sin Secure", "trustbound": "Violación de frontera de confianza",
}
CWE_CATEGORY = {
    89: "sqli", 564: "sqli", 78: "cmdi", 77: "cmdi", 94: "code", 95: "code", 502: "deser",
    22: "path", 23: "path", 36: "path", 73: "path", 79: "xss", 80: "xss", 918: "ssrf",
    327: "crypto", 328: "crypto", 326: "crypto", 916: "crypto", 759: "crypto", 330: "random",
    338: "random", 798: "secret", 259: "secret", 321: "secret", 547: "secret", 347: "jwt",
    489: "config", 215: "config", 295: "config", 942: "config", 1004: "config", 614: "securecookie",
    90: "ldapi", 643: "xpathi", 611: "xxe", 776: "xxe", 601: "redirect", 501: "trustbound",
}
BANDIT_CATEGORY = {
    "B102": "code", "B307": "code", "B105": "secret", "B106": "secret", "B107": "secret",
    "B201": "config", "B104": "config", "B501": "config", "B502": "config", "B503": "config",
    "B504": "config", "B301": "deser", "B302": "deser", "B506": "deser", "B614": "deser",
    "B303": "crypto", "B304": "crypto", "B305": "crypto", "B324": "crypto", "B505": "crypto",
    "B311": "random", "B310": "ssrf", "B602": "cmdi", "B605": "cmdi", "B609": "cmdi",
    "B608": "sqli", "B610": "sqli", "B611": "sqli", "B701": "xss", "B703": "xss", "B704": "xss",
    **{f"B{n}": "xxe" for n in range(313, 321)},
}
TOOLS = ("SAST Studio", "Bandit", "Semgrep CE")


def _cwe_numbers(values) -> list[int]:
    out = []
    for v in values or []:
        out += [int(n) for n in re.findall(r"CWE-(\d+)", str(v))]
    return out


def category_of_cwes(values) -> str | None:
    for n in _cwe_numbers(values):
        if n in CWE_CATEGORY:
            return CWE_CATEGORY[n]
    return None


@dataclass(frozen=True)
class Hit:
    path: str          # relativo a la raíz del corpus, con "/"
    start: int
    end: int
    category: str


@dataclass
class ToolRun:
    tool: str
    hits: list[Hit] = field(default_factory=list)
    seconds: float = 0.0
    error: str | None = None


# --- Adaptadores -------------------------------------------------------------------------------

def run_sast_studio(root: Path) -> ToolRun:
    from ..engine.runner import Engine
    from ..rules.registry import default_ruleset

    cwe = {r.meta.id: r.meta.cwe for r in default_ruleset()}
    t0 = time.perf_counter()
    # Los casos anotados viven en una carpeta de pruebas: se analizan explícitamente.
    files = [(p.relative_to(root).as_posix(), p.read_text(encoding="utf-8", errors="replace"))
             for p in sorted(root.rglob("*.py"))]
    report = Engine().scan_files(files, apply_excludes=False)
    run = ToolRun("SAST Studio", seconds=time.perf_counter() - t0)
    for f in report.findings:
        cat = category_of_cwes(cwe.get(f.rule_id, ()))
        if cat and not f.suppressed:
            run.hits.append(Hit(f.path, f.line, f.end_line or f.line, cat))
    return run


def run_bandit(root: Path) -> ToolRun:
    exe = shutil.which("bandit")
    if exe is None:
        return ToolRun("Bandit", error="bandit no está instalado")
    t0 = time.perf_counter()
    proc = subprocess.run([exe, "-r", str(root), "-f", "json", "-q", "--exit-zero"],
                          capture_output=True, text=True, encoding="utf-8")
    run = ToolRun("Bandit", seconds=time.perf_counter() - t0)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        run.error = (proc.stderr or proc.stdout)[-300:]
        return run
    for r in data.get("results", []):
        cat = BANDIT_CATEGORY.get(r["test_id"]) or category_of_cwes([f"CWE-{(r.get('issue_cwe') or {}).get('id')}"])
        if cat:
            rel = Path(r["filename"]).resolve().relative_to(root.resolve()).as_posix()
            lines = r.get("line_range") or [r["line_number"]]
            run.hits.append(Hit(rel, min(lines), max(lines), cat))
    return run


def run_semgrep(root: Path, configs: tuple[str, ...] = ("p/python", "p/secrets"),
                image: str = "semgrep/semgrep:1.100.0") -> ToolRun:
    args = ["semgrep", "scan", "--json", "--metrics=off", "--quiet", *[f"--config={c}" for c in configs]]
    # Primero la imagen Docker con versión fija (reproducible y Semgrep no funciona en Windows
    # nativo: allí corre pero no devuelve resultados); si no hay Docker, el binario local.
    local = shutil.which("semgrep")
    if shutil.which("docker"):
        cmd = ["docker", "run", "--rm", "-v", f"{root.resolve()}:/src:ro", image, *args, "/src"]
        prefix = "/src"
    elif local:
        cmd, prefix = [local, *args[1:], str(root)], str(root.resolve())
    else:
        return ToolRun("Semgrep CE", error="ni semgrep ni docker están disponibles")
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          env={**__import__("os").environ, "MSYS_NO_PATHCONV": "1"})
    run = ToolRun("Semgrep CE", seconds=time.perf_counter() - t0)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        run.error = (proc.stderr or proc.stdout)[-300:]
        return run
    for r in data.get("results", []):
        cat = category_of_cwes(r.get("extra", {}).get("metadata", {}).get("cwe"))
        if cat:
            rel = r["path"].replace("\\", "/").removeprefix(prefix.replace("\\", "/")).lstrip("/")
            run.hits.append(Hit(rel, r["start"]["line"], r["end"]["line"], cat))
    return run


# --- Corpus anotado -----------------------------------------------------------------------------

@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None


def ground_truth(cases_dir: Path) -> list[tuple[str, int, str, bool]]:
    """(archivo, línea, categoría, vulnerable) por cada anotación de un caso Python."""
    from ..rules.registry import default_ruleset

    cwe = {r.meta.id: r.meta.cwe for r in default_ruleset()}
    out = []
    for case in case_files(cases_dir):
        if case.suffix != ".py":
            continue
        exp = parse_expectations(case)
        for bucket, vulnerable in ((exp.must, True), (exp.todo_must, True), (exp.must_not, False), (exp.todo_must_not, False)):
            for rule_id, line in bucket:
                cat = category_of_cwes(cwe.get(rule_id, ()))
                if cat:
                    out.append((case.name, line, cat, vulnerable))
    return out


def score(truth, run: ToolRun) -> dict[str, Score]:
    scores: dict[str, Score] = {}
    for path, line, cat, vulnerable in truth:
        found = any(h.path == path and h.category == cat and h.start <= line <= h.end for h in run.hits)
        s = scores.setdefault(cat, Score())
        if vulnerable:
            s.tp, s.fn = s.tp + found, s.fn + (not found)
        else:
            s.fp, s.tn = s.fp + found, s.tn + (not found)
    total = Score()
    for s in scores.values():
        total.tp, total.fp, total.fn, total.tn = total.tp + s.tp, total.fp + s.fp, total.fn + s.fn, total.tn + s.tn
    scores["__total__"] = total
    return scores


# --- Informe ------------------------------------------------------------------------------------

def _pct(v: float | None) -> str:
    return "—" if v is None else f"{v * 100:.0f} %"


def run_all(root: Path) -> list[ToolRun]:
    return [run_sast_studio(root), run_bandit(root), run_semgrep(root)]


def annotated_report(cases_dir: Path) -> tuple[str, list[ToolRun]]:
    truth = ground_truth(cases_dir)
    runs = run_all(cases_dir)
    results = {r.tool: score(truth, r) for r in runs}
    vuln = sum(1 for t in truth if t[3])
    lines = [f"Corpus: `{cases_dir.as_posix()}` · {vuln} líneas vulnerables y {len(truth) - vuln} líneas seguras anotadas.\n",
             "| Herramienta | Aciertos | Falsos positivos | No detectados | Precisión | Recall | Tiempo |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for r in runs:
        if r.error:
            lines.append(f"| {r.tool} | error: {r.error[:60]} | | | | | |")
            continue
        t = results[r.tool]["__total__"]
        lines.append(f"| {r.tool} | {t.tp} | {t.fp} | {t.fn} | {_pct(t.precision)} | {_pct(t.recall)} | {r.seconds:.1f} s |")
    cats = sorted({t[2] for t in truth}, key=lambda c: CATEGORY_LABEL[c])
    lines += ["", "Recall por categoría (aciertos / líneas vulnerables; entre paréntesis, falsos positivos):\n",
              "| Categoría | " + " | ".join(r.tool for r in runs) + " |", "|---|" + "---:|" * len(runs)]
    for c in cats:
        cells = []
        for r in runs:
            s = results.get(r.tool, {}).get(c, Score()) if not r.error else Score()
            cells.append(f"{s.tp}/{s.tp + s.fn}" + (f" ({s.fp})" if s.fp else ""))
        lines.append(f"| {CATEGORY_LABEL[c]} | " + " | ".join(cells) + " |")
    return "\n".join(lines), runs


def real_report(name: str, root: Path) -> str:
    runs = run_all(root)
    cats = sorted({h.category for r in runs for h in r.hits}, key=lambda c: CATEGORY_LABEL[c])
    files = sum(1 for _ in root.rglob("*.py"))
    lines = [f"**{name}** ({files} archivos .py)\n", "| Categoría | " + " | ".join(r.tool for r in runs) + " |",
             "|---|" + "---:|" * len(runs)]
    for c in cats:
        lines.append(f"| {CATEGORY_LABEL[c]} | " + " | ".join(str(sum(h.category == c for h in r.hits)) for r in runs) + " |")
    lines.append("| **Total** | " + " | ".join(
        f"error: {r.error[:40]}" if r.error else f"**{len(r.hits)}**" for r in runs) + " |")
    lines.append("| Tiempo | " + " | ".join(f"{r.seconds:.1f} s" for r in runs) + " |")
    return "\n".join(lines)


# --- OWASP Benchmark for Python -----------------------------------------------------------------
# https://github.com/OWASP-Benchmark/BenchmarkPython (GPL-3.0: se descarga, no se copia al repo).
# Cada BenchmarkTestNNNNN.py es vulnerable o no para una categoría. Una herramienta "marca" el
# test si informa esa categoría en ese archivo. Puntuación de OWASP: Youden = TPR - FPR.

OWASP_CATEGORY = {
    "cmdi": "cmdi", "codeinj": "code", "deserialization": "deser", "hash": "crypto",
    "pathtraver": "path", "sqli": "sqli", "weakrand": "random", "xss": "xss", "ldapi": "ldapi",
    "xpathi": "xpathi", "xxe": "xxe", "redirect": "redirect", "securecookie": "securecookie",
    "trustbound": "trustbound",
}


def owasp_expected(csv_path: Path) -> list[tuple[str, str, bool]]:
    out = []
    for line in csv_path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name, cat, real, _cwe = [c.strip() for c in line.split(",")[:4]]
        out.append((f"{name}.py", OWASP_CATEGORY[cat], real.lower() == "true"))
    return out


def owasp_report(bench_root: Path) -> tuple[str, dict]:
    expected = owasp_expected(next(bench_root.glob("expectedresults-*.csv")))
    code = bench_root / "testcode"
    runs = run_all(code)
    cats = sorted({c for _, c, _ in expected}, key=lambda c: CATEGORY_LABEL[c])
    table: dict = {}
    for r in runs:
        flagged = {(h.path.rsplit("/", 1)[-1], h.category) for h in r.hits}
        for c in cats:
            tp = fn = fp = tn = 0
            for name, cat, real in expected:
                if cat != c:
                    continue
                hit = (name, c) in flagged
                if real:
                    tp, fn = tp + hit, fn + (not hit)
                else:
                    fp, tn = fp + hit, tn + (not hit)
            tpr = tp / (tp + fn) if tp + fn else 0.0
            fpr = fp / (fp + tn) if fp + tn else 0.0
            table[(r.tool, c)] = (tpr, fpr, tpr - fpr)
    # Categorías para las que SAST Studio TIENE reglas de Python (no las que salieron bien).
    from ..rules.registry import default_ruleset

    ours = {category_of_cwes(r.meta.cwe) for r in default_ruleset() if "python" in r.meta.languages
            or "any" in r.meta.languages}
    covered = [c for c in cats if c in ours]
    lines = [f"{len(expected)} casos de prueba ({sum(e[2] for e in expected)} vulnerables de verdad), "
             f"{len(cats)} categorías. Celda: **Youden** (TPR / FPR), en puntos porcentuales.\n",
             "| Categoría | " + " | ".join(r.tool for r in runs) + " |", "|---|" + "---:|" * len(runs)]
    for c in cats:
        cells = []
        for r in runs:
            tpr, fpr, y = table[(r.tool, c)]
            cells.append(f"**{y * 100:+.0f}** ({tpr * 100:.0f} / {fpr * 100:.0f})")
        lines.append(f"| {CATEGORY_LABEL[c]} | " + " | ".join(cells) + " |")
    def avg(tool, subset):
        vals = [table[(tool, c)][2] for c in subset]
        return sum(vals) / len(vals) * 100 if vals else 0.0
    lines.append(f"| **Media, las {len(cats)} categorías** | " + " | ".join(f"**{avg(r.tool, cats):+.0f}**" for r in runs) + " |")
    lines.append(f"| **Media, las {len(covered)} que cubre SAST Studio** | "
                 + " | ".join(f"**{avg(r.tool, covered):+.0f}**" for r in runs) + " |")
    lines.append("| Tiempo | " + " | ".join(f"{r.seconds:.1f} s" + (f" (error: {r.error[:30]})" if r.error else "") for r in runs) + " |")
    return "\n".join(lines), {"runs": runs, "table": table, "covered": covered}
