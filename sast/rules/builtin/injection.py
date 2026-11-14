"""Reglas de inyección basadas en taint (Python).

Todas leen `ctx.taint`, que se calcula una sola vez por archivo. Un flujo
fuente -> sink produce un hallazgo `path-problem` con la traza paso a paso.
Además, las reglas SQL y de comandos tienen una variante heurística de menor
confianza cuando el argumento se construye dinámicamente con datos de origen
desconocido (p. ej. un parámetro de función).
"""

from __future__ import annotations

import re
from typing import ClassVar, Iterable

from ..api import Confidence, Finding, PythonRule, RuleMeta, Severity
from ..registry import register

_SQL_KEYWORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|MERGE)\b", re.I)


class TaintRule(PythonRule):
    node_types = ()
    sink_kinds: ClassVar[tuple[str, ...]] = ()

    def flows(self, ctx) -> Iterable[Finding]:
        for flow in ctx.taint.flows_for(*self.sink_kinds):
            loc = flow.location
            yield self.finding(
                ctx,
                line=loc.line, col=loc.col, end_line=loc.end_line, end_col=loc.end_col,
                confidence=(Confidence.LOW if flow.approx
                            else Confidence.MEDIUM if flow.interprocedural else Confidence.HIGH),
                trace=flow.trace,
                variant=("approximate" if flow.approx else "interprocedural" if flow.interprocedural else "taint"),
                source=flow.source, sink=f"`{flow.sink}()`",
            )

    def heuristics(self, ctx) -> Iterable[Finding]:
        return ()

    def check(self, ctx, node) -> Iterable[Finding]:
        if ctx.tree is None:
            return
        yield from self.flows(ctx)
        yield from self.heuristics(ctx)


def _dynamic_unknown(site) -> bool:
    return site.dynamic and site.value.unknown and not site.value.live(site.kind)


@register
class SqlInjection(TaintRule):
    sink_kinds = ("sql",)
    meta = RuleMeta(
        id="py/sql-injection",
        name="Inyección SQL",
        message="Una entrada no confiable ({source}) llega a una consulta SQL ({sink}) sin parametrizar.",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        languages=("python",),
        cwe=("CWE-89",),
        owasp=("A03:2021",),
        kind="path-problem",
        engine="taint",
        security_severity=9.8,
        previous_ids=("SQL_INJECTION",),
        references=("https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"),
        explanation=(
            "La consulta SQL se construye pegando texto que viene del usuario. Un atacante puede cerrar la "
            "comilla y añadir su propio SQL (por ejemplo `' OR '1'='1`) para leer, modificar o borrar datos."
        ),
        remediation=(
            "Usa consultas parametrizadas: deja marcadores (`?` o `%s`) en el SQL y pasa los valores aparte, "
            "como segundo argumento de `execute()`. Nunca construyas SQL con `+`, `%`, f-strings ni `.format()`."
        ),
        example_bad='uid = request.args.get("id")\ncursor.execute("SELECT * FROM users WHERE id = \'%s\'" % uid)',
        example_good='uid = request.args.get("id")\ncursor.execute("SELECT * FROM users WHERE id = ?", (uid,))',
    )

    def heuristics(self, ctx) -> Iterable[Finding]:
        for site in ctx.taint.sinks_for("sql"):
            if _dynamic_unknown(site) and _SQL_KEYWORDS.search(site.literal):
                loc = site.location
                yield self.finding(
                    ctx, line=loc.line, col=loc.col, end_line=loc.end_line, end_col=loc.end_col,
                    confidence=Confidence.MEDIUM, variant="dynamic-query",
                    message=f"La consulta SQL de `{site.sink}()` se construye dinámicamente con datos de origen desconocido. "
                            "Usa parámetros en lugar de concatenar.",
                )


@register
class CommandInjection(TaintRule):
    sink_kinds = ("shell",)
    meta = RuleMeta(
        id="py/command-injection",
        name="Inyección de comandos del sistema",
        message="Una entrada no confiable ({source}) llega a un comando del sistema ({sink}).",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        languages=("python",),
        cwe=("CWE-78",),
        owasp=("A03:2021",),
        kind="path-problem",
        engine="taint",
        security_severity=9.8,
        previous_ids=("COMMAND_INJECTION", "SHELL_TRUE"),
        supersedes=("py/dangerous-function",),
        references=("https://owasp.org/www-community/attacks/Command_Injection",
                    "https://docs.python.org/3/library/subprocess.html#security-considerations"),
        explanation=(
            "El programa ejecuta un comando del sistema operativo construido con datos del usuario. Con "
            "caracteres como `;`, `&&` o `$(...)` el atacante encadena sus propios comandos en el servidor."
        ),
        remediation=(
            "Evita la shell: usa `subprocess.run([...])` con una lista de argumentos y `shell=False`. Si de "
            "verdad necesitas una cadena, escapa cada valor con `shlex.quote()` y valida contra una lista blanca."
        ),
        example_bad='host = request.args.get("host")\nos.system("ping -c 1 " + host)',
        example_good='host = request.args.get("host")\nsubprocess.run(["ping", "-c", "1", host], check=True)',
    )

    def heuristics(self, ctx) -> Iterable[Finding]:
        for site in ctx.taint.sinks_for("shell"):
            if _dynamic_unknown(site):
                loc = site.location
                yield self.finding(
                    ctx, line=loc.line, col=loc.col, end_line=loc.end_line, end_col=loc.end_col,
                    confidence=Confidence.LOW, variant="dynamic-command",
                    message=f"`{site.sink}()` ejecuta una cadena construida dinámicamente a través de la shell. "
                            "Usa una lista de argumentos sin shell.",
                )


@register
class PathTraversal(TaintRule):
    sink_kinds = ("path",)
    meta = RuleMeta(
        id="py/path-traversal",
        name="Path traversal (acceso a rutas arbitrarias)",
        message="Una entrada no confiable ({source}) se usa como ruta de archivo en {sink}.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        languages=("python",),
        cwe=("CWE-22",),
        owasp=("A01:2021",),
        kind="path-problem",
        engine="taint",
        security_severity=7.5,
        previous_ids=("PATH_TRAVERSAL",),
        references=("https://owasp.org/www-community/attacks/Path_Traversal",),
        explanation=(
            "El nombre de archivo viene del usuario y se usa tal cual. Con `../` el atacante sale de la carpeta "
            "prevista y lee o borra archivos del servidor, como `/etc/passwd` o la configuración con secretos."
        ),
        remediation=(
            "Reduce el nombre a su parte final con `os.path.basename()` o `secure_filename()`, únelo a un "
            "directorio base y comprueba con `os.path.realpath()` que el resultado sigue dentro de ese directorio."
        ),
        example_bad='name = request.args.get("f")\nreturn open("/srv/files/" + name).read()',
        example_good='name = secure_filename(request.args.get("f"))\nreturn send_from_directory("/srv/files", name)',
    )


@register
class Xss(TaintRule):
    sink_kinds = ("xss",)
    meta = RuleMeta(
        id="py/xss",
        name="Cross-Site Scripting (XSS)",
        message="Una entrada no confiable ({source}) se devuelve como HTML sin escapar en {sink}.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        languages=("python",),
        cwe=("CWE-79",),
        owasp=("A03:2021",),
        kind="path-problem",
        engine="taint",
        security_severity=6.1,
        previous_ids=("XSS",),
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",),
        explanation=(
            "Texto del usuario se inserta en una página HTML sin escapar. Si contiene `<script>`, el navegador "
            "de otra persona lo ejecuta y el atacante puede robar su sesión o actuar en su nombre."
        ),
        remediation=(
            "Usa `render_template()` con plantillas Jinja2 (escapan por defecto) en lugar de "
            "`render_template_string()` con texto concatenado. Si debes construir HTML, aplica `html.escape()`."
        ),
        example_bad='name = request.args.get("n")\nreturn render_template_string("<h1>Hola " + name + "</h1>")',
        example_good='name = request.args.get("n")\nreturn render_template("saludo.html", name=name)',
    )


@register
class Ssrf(TaintRule):
    sink_kinds = ("ssrf",)
    meta = RuleMeta(
        id="py/ssrf",
        name="Server-Side Request Forgery (SSRF)",
        message="Una entrada no confiable ({source}) decide la URL de una petición saliente ({sink}).",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        languages=("python",),
        cwe=("CWE-918",),
        owasp=("A10:2021",),
        kind="path-problem",
        engine="taint",
        security_severity=8.6,
        previous_ids=("SSRF",),
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",),
        explanation=(
            "El servidor hace una petición HTTP a una URL que elige el usuario. El atacante puede apuntar a "
            "servicios internos (`http://localhost:...`, `169.254.169.254` en la nube) que no deberían ser accesibles."
        ),
        remediation=(
            "No aceptes URLs completas del usuario: acepta un identificador y construye la URL en el servidor, "
            "o valida el esquema y el host contra una lista blanca antes de hacer la petición."
        ),
        example_bad='url = request.args.get("url")\nreturn requests.get(url).text',
        example_good='ALLOWED = {"status": "https://api.example.com/status"}\nreturn requests.get(ALLOWED[request.args["svc"]], timeout=5).text',
    )
