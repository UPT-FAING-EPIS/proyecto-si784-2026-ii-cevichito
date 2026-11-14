"""Configuración insegura (TLS, debug, CORS) y validación débil de JWT."""

from __future__ import annotations

import ast
from typing import Iterable

from ..api import Confidence, Finding, PythonRule, RuleMeta, Severity
from ..registry import register


def _kw(node: ast.Call, name: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_const(node: ast.AST | None, value: object) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) is type(value) and node.value == value


@register
class SecurityMisconfiguration(PythonRule):
    node_types = (ast.Call,)
    meta = RuleMeta(
        id="py/security-misconfiguration",
        name="Configuración de seguridad insegura",
        message="Configuración insegura: {variant}.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        languages=("python",),
        cwe=("CWE-295", "CWE-489", "CWE-942"),
        owasp=("A05:2021",),
        security_severity=7.4,
        previous_ids=("SECURITY_MISCONFIGURATION",),
        references=("https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",),
        explanation=(
            "Desactivar la verificación TLS permite que un intermediario lea o altere el tráfico; el modo debug de "
            "Flask expone una consola que ejecuta código; y CORS con `*` deja que cualquier web llame a tu API."
        ),
        remediation=(
            "Mantén `verify=True` (o pasa la ruta de tu CA), arranca en producción sin `debug=True` y limita "
            "CORS a una lista explícita de orígenes."
        ),
        example_bad='requests.get(url, verify=False)\napp.run(debug=True)\nCORS(app, origins="*")',
        example_good='requests.get(url, timeout=10)\napp.run()\nCORS(app, origins=["https://app.example.com"])',
    )

    def check(self, ctx, node) -> Iterable[Finding]:
        qn = ctx.qualname(node) or ""
        verify = _kw(node, "verify")
        if _is_const(verify, False) and any(p in qn for p in ("requests", "httpx", "session", "client", "urllib3")):
            yield self.finding(ctx, node, variant="verificación TLS desactivada (verify=False)")
        if qn.endswith(".run") or qn == "run":
            if _is_const(_kw(node, "debug"), True):
                yield self.finding(ctx, node, variant="servidor en modo debug (debug=True)", confidence=Confidence.MEDIUM)
        if qn.endswith("_create_unverified_context"):
            yield self.finding(ctx, node, variant="contexto SSL sin verificación")
        if qn.rsplit(".", 1)[-1] == "CORS":
            origins = _kw(node, "origins")
            if _is_const(origins, "*"):
                yield self.finding(ctx, node, variant='CORS abierto a cualquier origen (origins="*")', confidence=Confidence.MEDIUM)


@register
class JwtWeakness(PythonRule):
    node_types = (ast.Call,)
    meta = RuleMeta(
        id="py/jwt-weakness",
        name="Validación insegura de JWT",
        message="El token JWT se acepta sin verificar su firma ({variant}).",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        languages=("python",),
        cwe=("CWE-347",),
        owasp=("A07:2021",),
        security_severity=8.1,
        previous_ids=("JWT_WEAKNESS",),
        references=("https://datatracker.ietf.org/doc/html/rfc8725",),
        explanation=(
            "Si no se verifica la firma, o se acepta el algoritmo `none`, cualquiera puede fabricar un token con "
            "el usuario o los permisos que quiera, y la aplicación lo dará por bueno."
        ),
        remediation=(
            "Llama a `jwt.decode(token, clave, algorithms=[\"HS256\"])` fijando la lista de algoritmos y sin "
            "desactivar `verify_signature`. Nunca incluyas `none` entre los algoritmos permitidos."
        ),
        example_bad='jwt.decode(token, options={"verify_signature": False})',
        example_good='jwt.decode(token, SECRET, algorithms=["HS256"])',
    )

    def check(self, ctx, node) -> Iterable[Finding]:
        qn = ctx.qualname(node) or ""
        if not qn.startswith("jwt.") and not qn.endswith(".jwt.decode"):
            return
        method = qn.rsplit(".", 1)[-1]
        if method == "decode":
            if _is_const(_kw(node, "verify"), False):
                yield self.finding(ctx, node, variant="verify=False")
                return
            options = _kw(node, "options")
            if isinstance(options, ast.Dict):
                for k, v in zip(options.keys, options.values):
                    if _is_const(k, "verify_signature") and _is_const(v, False):
                        yield self.finding(ctx, node, variant="verify_signature=False")
                        return
            algorithms = _kw(node, "algorithms")
            if isinstance(algorithms, (ast.List, ast.Tuple)):
                for elt in algorithms.elts:
                    if isinstance(elt, ast.Constant) and str(elt.value).lower() == "none":
                        yield self.finding(ctx, node, variant='algoritmo "none" permitido')
                        return
        elif method == "encode":
            alg = _kw(node, "algorithm")
            if isinstance(alg, ast.Constant) and str(alg.value).lower() == "none":
                yield self.finding(ctx, node, variant='firma con algoritmo "none"')
