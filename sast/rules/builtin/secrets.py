"""Secretos escritos en el código (todos los lenguajes; análisis AST extra en Python)."""

from __future__ import annotations

import ast
import math
import re
from typing import Iterable

from ..api import Confidence, Finding, PythonRule, RuleMeta, Severity
from ..registry import register

SENSITIVE_NAME = re.compile(
    r"(?i)(passw(or)?d|passwd|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|auth[_-]?token|credential|contrase(ñ|n)a|clave)"
)
SENSITIVE_FUNC = re.compile(r"(?i)(pass(word)?|pwd|(^|_)(pw|hash)($|_)|secret|token|cred|auth)")

PATTERNS: list[tuple[re.Pattern[str], Confidence, str]] = [
    (re.compile(r"""(?i)\b([\w.-]*(?:password|passwd|pwd|secret|token|api_key|apikey|api_secret|private_key|access_key|auth_token)[\w-]*)["']?\s*[:=]\s*["']([^"'\s]{6,})["']"""), Confidence.HIGH, "assignment"),
    (re.compile(r"""["']((?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_\-]{20,})["']"""), Confidence.HIGH, "api-key"),
    (re.compile(r"""\b(gh[pousr]_[A-Za-z0-9]{30,})\b"""), Confidence.HIGH, "github-token"),
    (re.compile(r"""\b(AKIA[0-9A-Z]{16})\b"""), Confidence.HIGH, "aws-key"),
    (re.compile(r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"""), Confidence.HIGH, "private-key"),
    (re.compile(r"""(?i)\b(?:postgres(?:ql)?|mysql|mssql|oracle|mongodb(?:\+srv)?|redis|amqp)://[^\s"'<>:/@]*:([^\s"'<>@]{3,})@"""), Confidence.HIGH, "connection-string"),
]

PLACEHOLDERS = {
    "password", "pass", "test", "dummy", "example", "changeme", "change_me", "xxx", "xxxx", "***",
    "none", "null", "undefined", "default", "secret", "token", "key", "your_password", "your_api_key",
    "your_token", "placeholder", "redacted", "<password>", "****", "password123", "admin",
}


BENIGN_NAME_SUFFIX = re.compile(r"(?i)(_url|_uri|_endpoint|_msg|_message|_text|_label|_path|_file|_name|_key_name|_header|_field|_type|_prefix|_env|_var|_param|_id)$")


def _benign_assignment(name: str, value: str) -> bool:
    """Asignaciones con nombre sensible que no son secretos: URLs, mensajes, nombres de campo..."""
    v = value.strip()
    return (bool(BENIGN_NAME_SUFFIX.search(name)) or v.lower().startswith(("http://", "https://", "/"))
            or " " in v or _is_placeholder(v))


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"").lower()
    if not v or v in PLACEHOLDERS or len(v) < 6:
        return True
    if v.startswith(("your_", "your-", "<", "${", "{{", "%(")) or v.endswith(("_here", "-here", ">")):
        return True
    if re.fullmatch(r"[x*._-]+", v):
        return True
    return False


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


def looks_like_password(value: str) -> bool:
    if len(value) < 8 or any(c.isspace() for c in value) or _is_placeholder(value):
        return False
    classes = sum([any(c.islower() for c in value), any(c.isupper() for c in value),
                   any(c.isdigit() for c in value), any(not c.isalnum() for c in value)])
    return classes >= 3


def looks_like_random_secret(value: str) -> bool:
    if len(value) < 24 or any(c.isspace() for c in value) or "/" in value[:8]:
        return False
    if not (any(c.isdigit() for c in value) and any(c.isalpha() for c in value)):
        return False
    return entropy(value) >= 4.0


@register
class HardcodedSecret(PythonRule):
    node_types = ()
    meta = RuleMeta(
        id="generic/hardcoded-secret",
        name="Secreto escrito en el código",
        message="Posible secreto escrito en el código ({variant}). Muévelo a una variable de entorno o a un gestor de secretos.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        languages=("any",),
        cwe=("CWE-798",),
        owasp=("A07:2021",),
        engine="ast",
        security_severity=7.5,
        previous_ids=("HARDCODED_SECRET",),
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",),
        explanation=(
            "Una contraseña, token o clave aparece literalmente en el código. Cualquiera con acceso al "
            "repositorio (o a una copia filtrada) la obtiene, y cambiarla exige modificar y redesplegar el código."
        ),
        remediation=(
            "Lee el secreto del entorno (`os.environ[\"API_KEY\"]`) o de un gestor de secretos, sin valor por "
            "defecto: si falta, la aplicación no debe arrancar. Revoca el secreto expuesto, porque sigue en el historial."
        ),
        example_bad='API_KEY = "sk-live-abcdef1234567890abcdef"\nSECRET = os.environ.get("SECRET", "clave-por-defecto")',
        example_good='API_KEY = os.environ["API_KEY"]\nSECRET = os.environ["SECRET"]  # sin valor por defecto',
    )

    def check(self, ctx, node) -> Iterable[Finding]:
        by_line: dict[int, Finding] = {}

        def add(f: Finding) -> None:
            cur = by_line.get(f.line)
            if cur is None or f.confidence > cur.confidence:
                by_line[f.line] = f

        for number, text in enumerate(ctx.lines, start=1):
            if ctx.is_comment_line(number):
                continue
            for regex, confidence, variant in PATTERNS:
                m = regex.search(text)
                if not m:
                    continue
                if variant == "assignment":
                    name, value = m.group(1), m.group(2)
                    if _benign_assignment(name, value) or "{" in value or "%" in value:
                        continue
                add(self.finding(ctx, line=number, col=m.start(), end_col=m.end(), confidence=confidence, variant=variant))
                break

        if ctx.tree is not None:
            for f in self._python(ctx):
                add(f)
        return sorted(by_line.values(), key=lambda f: (f.line, f.col))

    def _python(self, ctx) -> Iterable[Finding]:
        for node in ctx.nodes:
            if isinstance(node, ast.Call):
                yield from self._call(ctx, node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                yield from self._assign(ctx, node)

    def _call(self, ctx, node: ast.Call) -> Iterable[Finding]:
        qn = ctx.qualname(node) or ""
        # 1. Valor por defecto de getenv / environ.get con nombre sensible
        if qn in {"os.getenv", "os.environ.get", "getenv", "environ.get"} or qn.endswith("environ.get"):
            key = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
            default = None
            if len(node.args) > 1:
                default = node.args[1]
            for kw in node.keywords:
                if kw.arg == "default":
                    default = kw.value
            if (isinstance(key, str) and SENSITIVE_NAME.search(key) and isinstance(default, ast.Constant)
                    and isinstance(default.value, str) and not _is_placeholder(default.value) and len(default.value) >= 8):
                yield self.finding(ctx, default, confidence=Confidence.HIGH, variant="env-default",
                                   message=f"`{key}` tiene un valor por defecto escrito en el código. Si la variable de "
                                           "entorno falta, la aplicación usa un secreto conocido por todos.")
            return
        # 2. Argumentos con nombre sensible: login(password="...")
        for kw in node.keywords:
            if kw.arg and SENSITIVE_NAME.search(kw.arg) and isinstance(kw.value, ast.Constant) \
                    and isinstance(kw.value.value, str) and not _is_placeholder(kw.value.value):
                yield self.finding(ctx, kw.value, variant="keyword-argument")
        # 3. Literal con forma de contraseña pasado a una función con nombre sensible
        fname = qn.rsplit(".", 1)[-1]
        if SENSITIVE_FUNC.search(fname) and not fname.startswith(("get", "check", "verify", "validate", "is_")):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and looks_like_password(arg.value):
                    yield self.finding(ctx, arg, variant="argument",
                                       message=f"Se pasa una contraseña literal a `{fname}()`. Léela del entorno o de un gestor de secretos.")
        # 4. Literales de alta entropía como argumento
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and looks_like_random_secret(arg.value):
                yield self.finding(ctx, arg, confidence=Confidence.LOW, variant="high-entropy-argument")

    def _assign(self, ctx, node) -> Iterable[Finding]:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        for t in targets:
            name = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else None
            if name and SENSITIVE_NAME.search(name) and not _benign_assignment(name, value.value):
                yield self.finding(ctx, value, confidence=Confidence.HIGH, variant="assignment")
            elif looks_like_random_secret(value.value):
                yield self.finding(ctx, value, confidence=Confidence.LOW, variant="high-entropy")
