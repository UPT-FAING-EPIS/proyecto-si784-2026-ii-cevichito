"""CLI `sast`: usa el mismo registro y el mismo runner que la API (RF-12)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from . import __version__
from .engine.runner import Engine, EngineConfig
from .reports import render_console, render_html, to_sarif
from .rules.api import Confidence, Severity
from .rules.registry import build_ruleset, default_ruleset

_SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _utf8_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:  # pragma: no cover
                pass


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="sast")
def main() -> None:
    """SAST Studio: análisis estático de seguridad con explicaciones en español."""
    _utf8_stdout()


@main.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option("-f", "--format", "fmt", type=click.Choice(["text", "json", "sarif", "html"]), default="text", show_default=True)
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path), help="Archivo de salida (por defecto, stdout).")
@click.option("--min-confidence", type=click.Choice(["low", "medium", "high"]), default="low", show_default=True)
@click.option("--min-severity", type=click.Choice(_SEVERITIES), default="info", show_default=True)
@click.option("--severity-threshold", type=click.Choice(_SEVERITIES), help="Sale con código 1 si hay hallazgos de esta severidad o mayor.")
@click.option("--include-tests/--exclude-tests", default=False, show_default=True, help="Incluir archivos de test.")
@click.option("--exclude", multiple=True, help="Patrón glob a excluir (repetible).")
@click.option("--rules", "rule_ids", help="IDs de reglas separados por comas.")
@click.option("--rules-dir", type=click.Path(exists=True, file_okay=False, path_type=Path), multiple=True, help="Directorio extra con reglas YAML.")
@click.option("--fail-on-rule-error", is_flag=True, help="Sale con código 2 si alguna regla falla.")
@click.option("-v", "--verbose", is_flag=True, help="Muestra trazas y cómo corregir.")
@click.option("--no-color", is_flag=True)
def scan(target: Path, fmt: str, output: Path | None, min_confidence: str, min_severity: str, severity_threshold: str | None,
         include_tests: bool, exclude: tuple[str, ...], rule_ids: str | None, rules_dir: tuple[Path, ...],
         fail_on_rule_error: bool, verbose: bool, no_color: bool) -> None:
    """Analiza TARGET (archivo o directorio)."""
    ruleset = build_ruleset(rules_dir) if rules_dir else default_ruleset()
    for err in ruleset.load_errors:
        click.echo(f"aviso: no se cargó {err.source}: {err.message}", err=True)
    if rule_ids:
        ruleset = ruleset.select(ids=[r.strip() for r in rule_ids.split(",") if r.strip()])
    config = EngineConfig(
        min_confidence=Confidence.parse(min_confidence),
        min_severity=Severity.parse(min_severity),
        exclude_tests=not include_tests,
        exclude_globs=exclude,
    )
    report = Engine(ruleset, config).scan_path(target)
    metas = ruleset.metas()
    if fmt == "json":
        text = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    elif fmt == "sarif":
        text = json.dumps(to_sarif(report, metas), indent=2, ensure_ascii=False)
    elif fmt == "html":
        text = render_html(report, metas)
    else:
        text = render_console(report, metas, color=not no_color and output is None and sys.stdout.isatty(), verbose=verbose)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        click.echo(f"Informe escrito en {output}", err=True)
    else:
        click.echo(text, nl=False)

    if fail_on_rule_error and report.rule_errors:
        sys.exit(2)
    if severity_threshold:
        threshold = Severity.parse(severity_threshold)
        if any(f.severity >= threshold for f in report.active_findings):
            sys.exit(1)


@main.command("rules")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text", show_default=True)
def list_rules(fmt: str) -> None:
    """Lista el catálogo de reglas."""
    ruleset = default_ruleset()
    if fmt == "json":
        click.echo(json.dumps([m.to_dict() for m in ruleset.metas()], indent=2, ensure_ascii=False))
        return
    for m in ruleset.metas():
        heur = " (heurística)" if m.engine == "heuristic" else ""
        click.echo(f"{m.id:<34} {m.severity.label:<9} {', '.join(m.cwe):<22} {m.name}{heur}")
    click.echo(f"\n{len(ruleset)} reglas")


@main.command("test-rules")
@click.argument("cases_dir", type=click.Path(exists=True, file_okay=False, path_type=Path), default=Path("tests/rules/cases"))
def test_rules(cases_dir: Path) -> None:
    """Ejecuta los casos anotados (# ruleid: / # ok:) de CASES_DIR."""
    from .testing import case_files, run_case

    failed = 0
    for case in case_files(cases_dir):
        res = run_case(case)
        status = "ok " if res.ok else "FALLA"
        click.echo(f"{status} {case.name}")
        for rid, line in res.missing:
            click.echo(f"      falta {rid} en la línea {line}")
        for rid, line in res.unexpected:
            click.echo(f"      sobra {rid} en la línea {line}")
        failed += not res.ok
    click.echo(f"\n{failed} casos fallidos" if failed else "\nTodos los casos pasan")
    sys.exit(1 if failed else 0)



@main.command("bench")
@click.option("--cases", "cases_dir", type=click.Path(exists=True, file_okay=False, path_type=Path),
              default=Path("tests/rules/cases"), show_default=True, help="Corpus anotado propio.")
@click.option("--owasp", "owasp_dir", type=click.Path(exists=True, file_okay=False, path_type=Path),
              help="Raíz de OWASP Benchmark for Python (con expectedresults-*.csv y testcode/).")
@click.option("--real", "real", multiple=True, metavar="NOMBRE=DIR",
              help="Repositorio real a describir (repetible), p. ej. 'vulpy (bad)=corpus/vulpy/bad'.")
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path), help="Archivo Markdown de salida.")
def bench(cases_dir: Path, owasp_dir: Path | None, real: tuple[str, ...], output: Path | None) -> None:
    """Compara SAST Studio con Bandit y Semgrep CE sobre los mismos archivos."""
    from . import bench as b

    parts = ["## 1. OWASP Benchmark for Python\n"]
    if owasp_dir:
        parts.append(b.owasp_report(owasp_dir)[0])
    else:
        parts.append("_No se pasó `--owasp`._")
    parts += ["\n## 2. Corpus anotado propio\n", b.annotated_report(cases_dir)[0], "\n## 3. Repositorios reales\n"]
    for item in real:
        name, _, path = item.partition("=")
        parts += [b.real_report(name.strip(), Path(path.strip())), ""]
    text = "\n".join(parts) + "\n"
    if output:
        output.write_text(text, encoding="utf-8")
        click.echo(f"Informe escrito en {output}")
    else:
        click.echo(text)


if __name__ == "__main__":  # pragma: no cover
    main()
