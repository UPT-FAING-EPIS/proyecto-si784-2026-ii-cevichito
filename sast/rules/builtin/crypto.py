"""Criptografía débil: cifrados obsoletos y hash de contraseñas inadecuado."""

from __future__ import annotations

import ast
import re
from typing import Iterable

from ..api import Confidence, Finding, PythonRule, RuleMeta, Severity
from ..registry import register

_WEAK_CIPHER_CALL = re.compile(
    r"^(?:Crypto|Cryptodome)\.Cipher\.(?P<alg>DES3?|ARC2|ARC4|Blowfish|CAST|XOR)\.new$"
    r"|^cryptography\.hazmat\.primitives\.ciphers\.algorithms\.(?P<alg2>TripleDES|ARC4|Blowfish|CAST5|IDEA|SEED)$"
)
_PASSWORD_NAME = re.compile(r"(?i)(passw(or)?d|passwd|pwd|contrase(ñ|n)a|clave)")
_FAST_HASH = re.compile(r"^hashlib\.(md5|sha1|sha224|sha256|sha384|sha512|sha3_\w+|blake2[bs]|new)$")


def _kw(node: ast.Call, name: str) -> ast.AST | None:
    return next((kw.value for kw in node.keywords if kw.arg == name), None)


@register
class WeakCipher(PythonRule):
    node_types = (ast.Call,)
    meta = RuleMeta(
        id="py/weak-cipher",
        name="Cifrado débil u obsoleto",
        message="Se usa {variant}, un cifrado o modo inseguro. Usa AES-GCM o ChaCha20-Poly1305.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        languages=("python",),
        cwe=("CWE-327",),
        owasp=("A02:2021",),
        security_severity=7.4,
        previous_ids=("WEAK_CIPHER_DES", "WEAK_CIPHER_RC4", "WEAK_CIPHER_ECB"),
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",),
        explanation=(
            "DES, 3DES, RC4 o Blowfish tienen claves cortas o debilidades conocidas, y el modo ECB cifra igual "
            "los bloques iguales, así que deja ver patrones del mensaje. Un atacante puede descifrar o manipular datos."
        ),
        remediation=(
            "Usa un cifrado autenticado moderno: AES en modo GCM (`AES.new(key, AES.MODE_GCM)`) o "
            "`cryptography.fernet.Fernet`, con claves de 256 bits generadas con `secrets`."
        ),
        example_bad="cipher = DES.new(key, DES.MODE_ECB)",
        example_good="cipher = AES.new(key, AES.MODE_GCM)",
    )

    def check(self, ctx, node) -> Iterable[Finding]:
        qn = ctx.qualname(node) or ""
        m = _WEAK_CIPHER_CALL.match(qn)
        if m:
            yield self.finding(ctx, node, variant=(m.group("alg") or m.group("alg2")).lower())
            return
        if qn.endswith(("RSA.generate", "rsa.generate_private_key", "DSA.generate", "dsa.generate_private_key")):
            size = _kw(node, "key_size") or _kw(node, "bits") or (node.args[0] if node.args else None)
            if isinstance(size, ast.Constant) and isinstance(size.value, int) and size.value < 2048:
                yield self.finding(ctx, node, variant=f"clave de {size.value} bits",
                                   message=f"Clave asimétrica de {size.value} bits: el mínimo recomendado es 2048 (mejor 3072).")
            return
        if qn.endswith("modes.ECB"):
            yield self.finding(ctx, node, variant="modo ecb")
            return
        args = [*node.args, *(kw.value for kw in node.keywords)]
        if any(isinstance(a, ast.Attribute) and a.attr == "MODE_ECB" for a in args):
            yield self.finding(ctx, node, variant="modo ecb")


@register
class InsecurePasswordHash(PythonRule):
    node_types = (ast.Assign, ast.AnnAssign, ast.Call)
    meta = RuleMeta(
        id="py/insecure-password-hash",
        name="Contraseña guardada con un hash rápido",
        message="La contraseña se procesa con `{variant}`, un hash rápido sin sal ni factor de trabajo. Usa bcrypt, Argon2 o scrypt.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        languages=("python",),
        cwe=("CWE-916",),
        owasp=("A02:2021",),
        security_severity=7.5,
        previous_ids=("INSECURE_PASSWORD_HASH",),
        references=("https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",),
        explanation=(
            "MD5 y SHA-* son rápidos a propósito: una GPU prueba miles de millones por segundo. Si se filtra la "
            "base de datos, las contraseñas guardadas así se recuperan por fuerza bruta o con tablas precalculadas."
        ),
        remediation=(
            "Usa una función diseñada para contraseñas, con sal y factor de trabajo: `bcrypt.hashpw()`, "
            "`argon2.PasswordHasher().hash()` o `werkzeug.security.generate_password_hash()`."
        ),
        example_bad='password = hashlib.sha256(raw.encode()).hexdigest()',
        example_good='password = bcrypt.hashpw(raw.encode(), bcrypt.gensalt())',
    )

    def _fast_hash_in(self, ctx, value: ast.AST) -> str | None:
        for sub in ast.walk(value):
            if isinstance(sub, ast.Call):
                qn = ctx.qualname(sub) or ""
                if _FAST_HASH.match(qn):
                    return qn
        return None

    def check(self, ctx, node) -> Iterable[Finding]:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [t.id if isinstance(t, ast.Name) else getattr(t, "attr", "") for t in targets]
            if node.value is not None and any(_PASSWORD_NAME.search(n or "") for n in names):
                qn = self._fast_hash_in(ctx, node.value)
                if qn:
                    yield self.finding(ctx, node, variant=qn)
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg and _PASSWORD_NAME.search(kw.arg):
                    qn = self._fast_hash_in(ctx, kw.value)
                    if qn:
                        yield self.finding(ctx, kw.value, variant=qn)
