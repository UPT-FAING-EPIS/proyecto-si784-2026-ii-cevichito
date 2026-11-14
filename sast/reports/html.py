"""Informe HTML autocontenido (sin JavaScript ni recursos externos)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from jinja2 import Environment, select_autoescape

from ..engine.runner import ScanReport
from ..rules.api import RuleMeta, Severity

_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe SAST Studio · {{ report.target }}</title>
<style>
:root { --bg:#ffffff; --fg:#1f2328; --muted:#59636e; --line:#d1d9e0; --panel:#f6f8fa;
        --crit:#a40e26; --high:#bc4c00; --med:#7d4e00; --low:#1a7f37; --info:#0969da; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --line:#30363d; --panel:#151b23;
          --crit:#ff7b72; --high:#ffa657; --med:#d29922; --low:#3fb950; --info:#58a6ff; }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:1080px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:20px; margin:0 0 4px; } h2 { font-size:16px; margin:32px 0 8px; }
.meta { color:var(--muted); margin:0 0 16px; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { font-weight:600; color:var(--muted); font-size:12px; }
code, pre { font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace; }
pre { background:var(--panel); border:1px solid var(--line); padding:8px; overflow-x:auto; margin:6px 0 0; }
.sev { font-weight:600; white-space:nowrap; }
.sev.critical { color:var(--crit); } .sev.high { color:var(--high); } .sev.medium { color:var(--med); }
.sev.low { color:var(--low); } .sev.info { color:var(--info); }
.counts td:first-child { width:160px; }
details summary { cursor:pointer; color:var(--muted); }
.tag { border:1px solid var(--line); padding:0 6px; font-size:12px; color:var(--muted); }
</style>
</head>
<body><main>
<h1>Informe de análisis estático</h1>
<p class="meta">{{ report.target }} · {{ report.files_scanned }} archivos · {{ report.loc_total }} líneas ·
motor v{{ report.engine_version }} · generado {{ generated }}</p>

<h2>Resumen</h2>
<table class="counts"><tbody>
{% for key in ["critical","high","medium","low","info"] %}
<tr><td><span class="sev {{ key }}">{{ labels[key] }}</span></td><td>{{ report.summary[key] }}</td></tr>
{% endfor %}
<tr><td>Suprimidos</td><td>{{ report.summary["suppressed"] }}</td></tr>
</tbody></table>

<h2>Hallazgos ({{ findings|length }})</h2>
{% if not findings %}<p>No se encontraron hallazgos activos.</p>{% else %}
<table>
<thead><tr><th>Severidad</th><th>Regla</th><th>Ubicación</th><th>Detalle</th></tr></thead>
<tbody>
{% for f in findings %}{% set m = metas.get(f.rule_id) %}
<tr>
<td><span class="sev {{ f.severity.label }}">{{ f.severity.label_es }}</span><br><span class="tag">confianza {{ f.confidence.label }}</span></td>
<td>{{ m.name if m else f.rule_id }}<br><code>{{ f.rule_id }}</code>{% if m and m.engine == "heuristic" %} <span class="tag">heurística</span>{% endif %}</td>
<td><code>{{ f.path }}:{{ f.line }}</code></td>
<td>{{ f.message }}
{% if f.snippet %}<pre>{{ f.snippet }}</pre>{% endif %}
{% if f.trace %}<details><summary>Traza ({{ f.trace|length }} pasos)</summary><ol>
{% for s in f.trace %}<li>línea {{ s.line }}: {{ s.description }}</li>{% endfor %}</ol></details>{% endif %}
{% if m %}<details><summary>Cómo corregirlo</summary><p>{{ m.explanation }}</p><p>{{ m.remediation }}</p>
<pre>{{ m.example_good }}</pre></details>{% endif %}
</td>
</tr>
{% endfor %}
</tbody></table>{% endif %}

{% if report.rule_errors %}
<h2>Errores de reglas</h2>
<ul>{% for e in report.rule_errors %}<li><code>{{ e.rule_id }}</code> en <code>{{ e.path }}</code>: {{ e.exc_type }}: {{ e.message }}</li>{% endfor %}</ul>
{% endif %}
</main></body></html>
"""

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
_template = _env.from_string(_TEMPLATE)


def render_html(report: ScanReport, rules: Iterable[RuleMeta]) -> str:
    return _template.render(
        report=report,
        findings=report.active_findings,
        metas={m.id: m for m in rules},
        labels={s.label: s.label_es.capitalize() for s in Severity},
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
