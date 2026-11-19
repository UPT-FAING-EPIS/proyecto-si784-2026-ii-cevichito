"""Intentos de retos: cada intento es un proyecto oculto del alumno; el veredicto sale de sus escaneos.

El primer escaneo del intento analiza el código de partida y sirve de base. Un envío se da por superado
cuando su escaneo terminado ya no contiene la regla del reto (ni silenciada con `# nosec`/`# sast: ignore`)
y no introduce hallazgos nuevos de severidad alta o crítica respecto a esa base.
"""

from __future__ import annotations

import ast

from sqlalchemy import select

from sast.rules.api import Severity

from ..challenges import Challenge, Requirement
from ..errors import ApiError
from ..extensions import db
from ..models.entities import Occurrence, Project, Scan, User, utcnow
from . import scan_jobs


def attempt_of(user: User, ch: Challenge) -> Project | None:
    return db.session.scalar(select(Project).where(Project.owner_id == user.id, Project.challenge_id == ch.id))


def attempts_by_challenge(user: User) -> dict[str, Project]:
    rows = db.session.scalars(select(Project).where(Project.owner_id == user.id, Project.challenge_id.is_not(None)))
    return {p.challenge_id: p for p in rows}


def check_submission(ch: Challenge, code: object, settings) -> str:
    """Valida el envío antes de encolarlo: Python válido y con las funciones del enunciado."""
    if not isinstance(code, str) or not code.strip():
        raise ApiError(422, "empty_code", "No hay código para comprobar.")
    if len(code.encode("utf-8")) > settings.max_snippet_kb * 1024:
        raise ApiError(413, "snippet_too_large", f"El código supera {settings.max_snippet_kb} KB.")
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise ApiError(422, "syntax_error", f"El código tiene un error de sintaxis en la línea {exc.lineno}: {exc.msg}.",
                       line=exc.lineno) from None
    functions = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    missing = [name for name in ch.keep if name not in functions]
    if missing:
        names = ", ".join(f"`{n}`" for n in missing)
        raise ApiError(422, "missing_functions",
                       f"Corrige el código sin borrarlo: falta la función {names} del enunciado.", functions=missing)
    for req in ch.requires:
        problem = _unmet(req, functions)
        if problem:
            raise ApiError(422, "behavior_missing",
                           f"Corrige el código sin borrarlo: tu función `{req.function}` {problem}.",
                           function=req.function)
    return code


# --- Comprobación de comportamiento (sin ejecutar el código) ----------------------------------------

def _dotted(node: ast.AST) -> str | None:
    """`a.b.c` para Name/Attribute; `?.c` si la base es otra expresión, p. ej. `get_db().execute`."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif parts:
        parts.append("?")
    else:
        return None
    return ".".join(reversed(parts))


def _reach(name: str, functions: dict, seen: set[str]) -> list[ast.AST]:
    """La función y las funciones del módulo que llama (el arreglo puede ir en un helper)."""
    if name in seen or name not in functions:
        return []
    seen.add(name)
    nodes = [functions[name]]
    for n in ast.walk(functions[name]):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
            nodes += _reach(n.func.id, functions, seen)
    return nodes


def _call_matches(dotted: str, spec: str) -> bool:
    last = spec.rsplit(".", 1)[-1]
    return dotted == spec or dotted.endswith("." + spec) or dotted == last or (
        "." not in spec and dotted.endswith("." + last))


def _unmet(req: Requirement, functions: dict) -> str | None:
    nodes = _reach(req.function, functions, set())
    calls, refs, texts, returns = set(), set(), [], False
    for fn in nodes:
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and (d := _dotted(n.func)):
                calls.add(d)
            if isinstance(n, (ast.Name, ast.Attribute)) and (d := _dotted(n)):
                parts = d.split(".")
                refs.update(".".join(parts[:i]) for i in range(1, len(parts) + 1))
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                texts.append(n.value)
            if isinstance(n, ast.Return) and n.value is not None and fn is nodes[0]:
                returns = True
    for group in req.calls:
        if not any(_call_matches(c, spec) for c in calls for spec in group):
            return f"ya no llama a `{group[0]}` (ni a una alternativa)"
    for group in req.uses:
        if not any(spec in refs for spec in group):
            return f"ya no usa `{group[0]}`"
    for group in req.texts:
        if not any(spec in s for s in texts for spec in group):
            return f"ya no envía `{group[0]}`"
    if req.returns and not returns:
        return "ya no devuelve una respuesta (`return`)"
    return None


def submit(user: User, ch: Challenge, code: object, settings, request_id: str | None = None) -> Scan:
    code = check_submission(ch, code, settings)
    project = attempt_of(user, ch)
    if project is None:
        project = Project(owner_id=user.id, name=f"reto:{ch.id}"[:120], challenge_id=ch.id)
        db.session.add(project)
        db.session.flush()
        # Base: el código de partida. Se encola antes que el envío para que el worker lo analice primero.
        scan_jobs.create_scan(user, project, source="snippet", filename=ch.filename, code=ch.starter,
                              settings=settings, request_id=request_id)
    return scan_jobs.create_scan(user, project, source="snippet", filename=ch.filename, code=code,
                                 settings=settings, request_id=request_id)


def _scans(project: Project) -> list[Scan]:
    return list(db.session.scalars(select(Scan).where(Scan.project_id == project.id)
                                   .order_by(Scan.queued_at, Scan.id)))


def _occurrences(scan: Scan) -> list[Occurrence]:
    return list(db.session.scalars(select(Occurrence).where(Occurrence.scan_id == scan.id)
                                   .order_by(Occurrence.start_line, Occurrence.id)))


def verdict(project: Project | None, ch: Challenge) -> dict:
    """Estado del intento: sin_empezar, analizando, error, sigue, silenciado, nuevo_fallo o superado."""
    out: dict = {"state": "sin_empezar", "scan_id": None, "submissions": 0, "solved_at": None,
                 "remaining": [], "silenced": [], "new": []}
    if project is None:
        return out
    out["solved_at"] = project.challenge_solved_at
    scans = _scans(project)
    if len(scans) < 2:
        return out
    base, last = scans[0], scans[-1]
    out["scan_id"] = last.id
    out["submissions"] = len(scans) - 1
    if not (base.finished and last.finished):
        out["state"] = "analizando"
        return out
    if base.status != "done" or last.status != "done" or last.partial:
        out["state"] = "error"
        return out

    targets = set(ch.rules)
    base_issues = {o.issue_id for o in _occurrences(base)}
    remaining, silenced, new = [], [], []
    for o in _occurrences(last):
        if o.issue.rule_id in targets:
            (silenced if o.suppressed else remaining).append(o)
        elif not o.suppressed and o.issue_id not in base_issues and o.severity >= int(Severity.HIGH):
            new.append(o)
    out.update(remaining=remaining, silenced=silenced, new=new)
    if remaining:
        out["state"] = "sigue"
    elif silenced:
        out["state"] = "silenciado"
    elif new:
        out["state"] = "nuevo_fallo"
    else:
        out["state"] = "superado"
        if project.challenge_solved_at is None:
            project.challenge_solved_at = utcnow()
            db.session.commit()
        out["solved_at"] = project.challenge_solved_at
    return out


def progress_state(project: Project | None) -> str:
    if project is None:
        return "sin_empezar"
    return "superado" if project.challenge_solved_at else "en_curso"
