"""Análisis de contaminación (taint) para Python, intra-archivo e inter-procedural.

Diseño (inspirado en Pysa):

1. Se calcula un *resumen* por función: qué parámetros llegan al valor de
   retorno, qué parámetros llegan a un sink y si la función devuelve una fuente.
   Los resúmenes se iteran hasta un punto fijo (cubre recursión y cualquier
   orden de definición).
2. Una pasada final recorre el módulo y cada función con fuentes reales y aplica
   los resúmenes en cada llamada local. Así `request.args -> helper(v) ->
   os.system(v)` se reporta en el sink de `helper` con la traza completa.

El resultado se calcula una sola vez por archivo y lo comparten todas las
reglas de taint (`FileContext.taint`).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..rules.api import TraceStep
from .models import TaintModels

MAX_TAINTS = 4
MAX_TRACE = 12
MAX_FIXPOINT_ROUNDS = 6

#: Funciones y métodos cuya salida se deriva directamente de la entrada.
EXACT_PROPAGATORS = frozenset({
    "str", "repr", "bytes", "format", "list", "tuple", "dict", "set", "sorted", "reversed",
    "strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize", "casefold", "replace", "split",
    "rsplit", "splitlines", "join", "encode", "decode", "removeprefix", "removesuffix", "zfill", "center",
    "ljust", "rjust", "get", "pop", "copy", "values", "items", "keys", "getlist", "partition", "rpartition",
    "os.path.join", "os.path.abspath", "os.path.normpath", "posixpath.join", "pathlib.Path", "Path",
    "urllib.parse.urljoin", "urljoin",
})

Resolver = Callable[[ast.AST], "str | None"]


# ---------------------------------------------------------------------------
# Valores abstractos
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Taint:
    origin: str                          # "source" o "param:<i>"
    description: str                     # p. ej. "Entrada HTTP del usuario (request.args.get)"
    trace: tuple[TraceStep, ...] = ()
    sanitized: frozenset[str] = frozenset()
    approx: bool = False                 # pasó por una función desconocida (propagación supuesta)

    def live_for(self, kind: str) -> bool:
        return "*" not in self.sanitized and kind not in self.sanitized

    def step(self, line: int, description: str) -> "Taint":
        if self.trace and self.trace[-1].line == line:
            return self
        trace = (self.trace + (TraceStep(line, description),))[-MAX_TRACE:]
        return Taint(self.origin, self.description, trace, self.sanitized, self.approx)

    def sanitize(self, kinds: Iterable[str]) -> "Taint":
        return Taint(self.origin, self.description, self.trace, self.sanitized | frozenset(kinds), self.approx)

    def approximate(self) -> "Taint":
        return self if self.approx else Taint(self.origin, self.description, self.trace, self.sanitized, True)

    @property
    def sort_key(self) -> tuple:
        return (self.origin, tuple((s.line, s.description) for s in self.trace), tuple(sorted(self.sanitized)), self.approx)


@dataclass(frozen=True)
class Val:
    """Valor abstracto: contaminaciones que lleva y si su origen es desconocido."""

    taints: tuple[Taint, ...] = ()
    unknown: bool = False

    def __or__(self, other: "Val") -> "Val":
        if not other.taints and not other.unknown:
            return self
        if not self.taints and not self.unknown:
            return other
        merged = {t.sort_key: t for t in self.taints + other.taints}
        taints = tuple(merged[k] for k in sorted(merged))[:MAX_TAINTS]
        return Val(taints, self.unknown or other.unknown)

    def step(self, line: int, description: str) -> "Val":
        if not self.taints:
            return self
        return Val(tuple(t.step(line, description) for t in self.taints), self.unknown)

    def live(self, kind: str, origin_prefix: str = "source") -> tuple[Taint, ...]:
        return tuple(t for t in self.taints if t.origin.startswith(origin_prefix) and t.live_for(kind))


CLEAN = Val()
UNKNOWN = Val(unknown=True)


def union(values: Iterable[Val]) -> Val:
    out = CLEAN
    for v in values:
        out = out | v
    return out


# ---------------------------------------------------------------------------
# Resultados
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Location:
    line: int
    col: int
    end_line: int
    end_col: int

    @classmethod
    def of(cls, node: ast.AST) -> "Location":
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0)
        return cls(line, col, getattr(node, "end_lineno", None) or line, getattr(node, "end_col_offset", None) or col)


@dataclass(frozen=True)
class Flow:
    kind: str
    sink: str                    # nombre calificado del sink
    location: Location
    source: str                  # descripción de la fuente
    trace: tuple[TraceStep, ...]
    interprocedural: bool = False
    approx: bool = False


@dataclass(frozen=True)
class SinkSite:
    """Cada llamada a un sink, contaminada o no (para reglas heurísticas)."""

    kind: str
    sink: str
    location: Location
    value: Val
    dynamic: bool                # el argumento se construye con +, %, f-string o .format
    function: str
    literal: str = ""            # texto de los literales del argumento (p. ej. "SELECT ... WHERE")


@dataclass(frozen=True)
class ParamSink:
    param: int
    kind: str
    sanitized: frozenset[str]
    sink: str
    location: Location
    trace: tuple[TraceStep, ...]


@dataclass(frozen=True)
class Summary:
    params: tuple[str, ...]
    param_to_return: tuple[Taint, ...] = ()
    returns_source: tuple[Taint, ...] = ()
    return_unknown: bool = False
    param_to_sink: tuple[ParamSink, ...] = ()


@dataclass
class TaintResult:
    flows: dict[str, list[Flow]] = field(default_factory=dict)
    sinks: list[SinkSite] = field(default_factory=list)
    summaries: dict[str, Summary] = field(default_factory=dict)

    def flows_for(self, *kinds: str) -> list[Flow]:
        out: list[Flow] = []
        for k in kinds:
            out.extend(self.flows.get(k, []))
        return out

    def sinks_for(self, *kinds: str) -> list[SinkSite]:
        return [s for s in self.sinks if s.kind in kinds]


# ---------------------------------------------------------------------------
# Análisis de un cuerpo de función o de módulo
# ---------------------------------------------------------------------------

def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def _literal_text(node: ast.AST) -> str:
    return " ".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))


def _kwarg_constant(call: ast.Call, name: str) -> object:
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant):
            return kw.value.value
    return None


def _short(qualname: str) -> str:
    return qualname.split(".")[-1] if qualname else "?"


class _BodyAnalyzer:
    def __init__(
        self,
        *,
        models: TaintModels,
        resolve: Resolver,
        functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        summaries: dict[str, Summary],
        globals_env: dict[str, Val],
        function_name: str,
        summary_mode: bool,
    ) -> None:
        self.models = models
        self.resolve = resolve
        self.functions = functions
        self.summaries = summaries
        self.globals = globals_env
        self.function_name = function_name
        self.summary_mode = summary_mode
        self.env: dict[str, Val] = {}
        # Cómo se construyó el texto de cada variable: (dinámico, literales). Así
        # `q = "..." % x; cur.execute(q)` se trata igual que `cur.execute("..." % x)`.
        self.built: dict[str, tuple[bool, str]] = {}
        self.ret: Val = CLEAN
        self.flows: list[Flow] = []
        self.sinks: list[SinkSite] = []
        self.param_sinks: list[ParamSink] = []

    # -- entorno ---------------------------------------------------------------
    def lookup(self, name: str) -> Val:
        if name in self.env:
            return self.env[name]
        if name in self.globals:
            return self.globals[name]
        return UNKNOWN

    def assign(self, target: ast.AST, value: Val, line: int) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = value.step(line, f"Se asigna a `{target.id}`")
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.assign(elt, value, line)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, value, line)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = target
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            if isinstance(base, ast.Name):
                self.env[base.id] = self.lookup(base.id) | value.step(line, f"Se guarda en `{base.id}`")

    def _record_built(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.built[target.id] = (_is_dynamic_string(value), _literal_text(value)[:500])

    # -- sentencias -------------------------------------------------------------
    def run_body(self, body: list[ast.stmt]) -> None:
        for stmt in body:
            self.stmt(stmt)

    def _branch(self, *bodies: list[ast.stmt]) -> None:
        before = dict(self.env)
        results = []
        for body in bodies:
            self.env = dict(before)
            self.run_body(body)
            results.append(self.env)
        merged: dict[str, Val] = {}
        for env in results:
            for k, v in env.items():
                merged[k] = merged[k] | v if k in merged else v
        self.env = merged

    def _loop(self, body: list[ast.stmt], orelse: list[ast.stmt]) -> None:
        """Cuerpo de bucle: una segunda pasada solo si la primera cambió el entorno."""
        before = dict(self.env)
        self._branch(body, [])
        if self.env != before:
            self._branch(body, [])
        if orelse:
            self._branch(orelse, [])

    def stmt(self, node: ast.stmt) -> None:
        if isinstance(node, ast.Assign):
            value = self.expr(node.value)
            for t in node.targets:
                self.assign(t, value, node.lineno)
                self._record_built(t, node.value)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.assign(node.target, self.expr(node.value), node.lineno)
                self._record_built(node.target, node.value)
        elif isinstance(node, ast.AugAssign):
            value = self.expr(node.value)
            if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
                # Añadir texto fijo (`q += " LIMIT %(n)s"`) no lo vuelve dinámico; añadir datos sí.
                dyn, lit = self.built.get(node.target.id, (False, ""))
                added_dyn = not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))
                self.built[node.target.id] = (dyn or added_dyn, f"{lit} {_literal_text(node.value)}"[:500])
            if isinstance(node.target, ast.Name):
                self.env[node.target.id] = self.lookup(node.target.id) | value.step(node.lineno, f"Se concatena a `{node.target.id}`")
            else:
                self.assign(node.target, value, node.lineno)
        elif isinstance(node, ast.Expr):
            self.expr(node.value)
        elif isinstance(node, ast.Return):
            if node.value is not None:
                self.ret = self.ret | self.expr(node.value).step(node.lineno, "Se devuelve")
        elif isinstance(node, ast.If):
            self.expr(node.test)
            self._branch(node.body, node.orelse)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self.assign(node.target, self.expr(node.iter), node.lineno)
            self._loop(node.body, node.orelse)
        elif isinstance(node, ast.While):
            self.expr(node.test)
            self._loop(node.body, node.orelse)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                value = self.expr(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, value, node.lineno)
            self.run_body(node.body)
        elif isinstance(node, ast.Try) or (hasattr(ast, "TryStar") and isinstance(node, getattr(ast, "TryStar"))):
            self.run_body(node.body)
            self._branch(*[h.body for h in node.handlers], node.orelse)
            self.run_body(node.finalbody)
        elif hasattr(ast, "Match") and isinstance(node, ast.Match):
            self.expr(node.subject)
            self._branch(*[c.body for c in node.cases])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return  # se analizan por separado
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.expr(child)

    # -- expresiones -------------------------------------------------------------
    def expr(self, node: ast.AST | None) -> Val:
        if node is None:
            return CLEAN
        if isinstance(node, ast.Constant):
            return CLEAN
        if isinstance(node, ast.Name):
            return self.lookup(node.id)
        if isinstance(node, ast.Attribute):
            qn = self.resolve(node)
            if qn:
                desc = self.models.match_source_attr(qn)
                if desc:
                    return Val((Taint("source", f"{desc} (`{qn}`)", (TraceStep(node.lineno, f"{desc}: `{qn}`"),)),))
            return self.expr(node.value)
        if isinstance(node, ast.Subscript):
            return self.expr(node.value)
        if isinstance(node, ast.BinOp):
            return self.expr(node.left) | self.expr(node.right)
        if isinstance(node, ast.BoolOp):
            return union(self.expr(v) for v in node.values)
        if isinstance(node, ast.UnaryOp):
            return self.expr(node.operand) if not isinstance(node.op, ast.Not) else CLEAN
        if isinstance(node, ast.Compare):
            for part in [node.left, *node.comparators]:
                self.expr(part)
            return CLEAN
        if isinstance(node, ast.IfExp):
            self.expr(node.test)
            return self.expr(node.body) | self.expr(node.orelse)
        if isinstance(node, ast.JoinedStr):
            return union(self.expr(v) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self.expr(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return union(self.expr(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return union(self.expr(v) for v in node.values)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self._comprehension(node.generators, [node.elt])
        if isinstance(node, ast.DictComp):
            return self._comprehension(node.generators, [node.key, node.value])
        if isinstance(node, (ast.Await, ast.Starred)):
            return self.expr(node.value)
        if isinstance(node, ast.NamedExpr):
            value = self.expr(node.value)
            self.assign(node.target, value, node.lineno)
            return value
        if isinstance(node, ast.Call):
            return self.call(node)
        if isinstance(node, ast.Lambda):
            return UNKNOWN
        return UNKNOWN

    def _comprehension(self, generators: list[ast.comprehension], elts: list[ast.expr]) -> Val:
        saved = dict(self.env)
        for gen in generators:
            self.assign(gen.target, self.expr(gen.iter), getattr(gen.iter, "lineno", 0))
            for cond in gen.ifs:
                self.expr(cond)
        out = union(self.expr(e) for e in elts)
        self.env = saved
        return out

    # -- llamadas ----------------------------------------------------------------
    def call(self, node: ast.Call) -> Val:
        qn = self.resolve(node.func) or ""
        args = [self.expr(a) for a in node.args]
        kwargs = {kw.arg: self.expr(kw.value) for kw in node.keywords}
        receiver = self.expr(node.func.value) if isinstance(node.func, ast.Attribute) else CLEAN

        self._check_sinks(node, qn, args, kwargs)

        # 1. Fuente
        desc = self.models.match_source_call(qn) if qn else None
        if desc:
            return Val((Taint("source", f"{desc} (`{qn}()`)", (TraceStep(node.lineno, f"{desc}: `{qn}()`"),)),))

        # 2. Sanitizador
        kinds = self.models.match_sanitizer(qn) if qn else None
        if kinds is not None:
            if "*" in kinds:
                return CLEAN
            inner = union(args) | union(kwargs.values())
            return Val(tuple(t.sanitize(kinds).step(node.lineno, f"Se sanea con `{qn}()`") for t in inner.taints), False)

        # 3. Función local con resumen
        if isinstance(node.func, ast.Name) and node.func.id in self.summaries:
            return self._apply_summary(node, node.func.id, args, kwargs)

        # 4. Llamada desconocida: propaga argumentos y receptor (Pysa). Los métodos de
        #    texto/colección conocidos propagan de forma exacta; el resto, aproximada.
        merged = receiver | union(args) | union(kwargs.values())
        exact = (isinstance(node.func, ast.Attribute) and node.func.attr in EXACT_PROPAGATORS) or qn in EXACT_PROPAGATORS
        if not exact and merged.taints:
            merged = Val(tuple(t.approximate() for t in merged.taints), merged.unknown)
        return merged | UNKNOWN

    def _arg_for(self, model_arg: int, node: ast.Call, args: list[Val]) -> tuple[Val, ast.AST | None]:
        if model_arg < len(args):
            return args[model_arg], node.args[model_arg]
        return CLEAN, None

    def _check_sinks(self, node: ast.Call, qn: str, args: list[Val], kwargs: dict) -> None:
        if not qn:
            return
        loc = Location.of(node)
        for model in self.models.match_sinks(qn):
            if model.when_kwarg and any(_kwarg_constant(node, k) != v for k, v in model.when_kwarg):
                continue
            value, arg_node = self._arg_for(model.arg, node, args)
            if arg_node is None:
                continue
            dynamic, literal = _is_dynamic_string(arg_node), _literal_text(arg_node)[:500]
            if isinstance(arg_node, ast.Name) and arg_node.id in self.built:
                dynamic, literal = self.built[arg_node.id]
            self.sinks.append(SinkSite(model.kind, qn, loc, value, dynamic, self.function_name, literal))
            sink_step = TraceStep(node.lineno, f"Llega a `{qn}()` ({self.models.sink_descriptions.get(model.kind, model.kind)})")
            for t in value.live(model.kind, "source"):
                self.flows.append(Flow(model.kind, qn, loc, t.description, t.trace + (sink_step,), approx=t.approx))
            if self.summary_mode:
                for t in value.live(model.kind, "param:"):
                    idx = int(t.origin.split(":", 1)[1])
                    self.param_sinks.append(ParamSink(idx, model.kind, t.sanitized, qn, loc, t.trace + (sink_step,)))

    def _apply_summary(self, node: ast.Call, fname: str, args: list[Val], kwargs: dict) -> Val:
        summary = self.summaries[fname]
        by_index: dict[int, Val] = {i: v for i, v in enumerate(args)}
        for name, val in kwargs.items():
            if name in summary.params:
                by_index[summary.params.index(name)] = val
        call_desc = f"Se pasa a `{fname}()`"

        # Flujos hacia sinks dentro de la función llamada
        for ps in summary.param_to_sink:
            arg = by_index.get(ps.param)
            if arg is None:
                continue
            for t in arg.taints:
                merged = t.sanitize(ps.sanitized)
                if not merged.live_for(ps.kind):
                    continue
                trace = (t.trace + (TraceStep(node.lineno, call_desc),) + ps.trace)[-MAX_TRACE:]
                if t.origin == "source":
                    self.flows.append(Flow(ps.kind, ps.sink, ps.location, t.description, trace,
                                           interprocedural=True, approx=t.approx))
                elif self.summary_mode:
                    idx = int(t.origin.split(":", 1)[1])
                    self.param_sinks.append(ParamSink(idx, ps.kind, merged.sanitized, ps.sink, ps.location, trace))

        # Valor de retorno
        out = Val(tuple(t.step(node.lineno, f"Devuelto por `{fname}()`") for t in summary.returns_source), summary.return_unknown)
        for rt in summary.param_to_return:
            idx = int(rt.origin.split(":", 1)[1])
            arg = by_index.get(idx)
            if arg is None:
                continue
            for t in arg.taints:
                out = out | Val((t.sanitize(rt.sanitized).step(node.lineno, f"Devuelto por `{fname}()`"),))
            out = out | Val((), arg.unknown)
        return out


# ---------------------------------------------------------------------------
# Orquestación
# ---------------------------------------------------------------------------

def _collect_functions(nodes: Iterable[ast.AST]) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    out: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[node.name] = node
    return out


def _param_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    a = fn.args
    return tuple(p.arg for p in [*a.posonlyargs, *a.args, *a.kwonlyargs])


def analyze(tree: ast.Module, models: TaintModels, resolve: Resolver,
            nodes: list[ast.AST] | None = None) -> TaintResult:
    nodes = nodes if nodes is not None else list(ast.walk(tree))
    functions = _collect_functions(nodes)
    called = {n.func.id for n in nodes
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in functions}

    def make(name: str, summaries: dict[str, Summary], globals_env: dict[str, Val], summary_mode: bool) -> _BodyAnalyzer:
        return _BodyAnalyzer(models=models, resolve=resolve, functions=functions, summaries=summaries,
                             globals_env=globals_env, function_name=name, summary_mode=summary_mode)

    # Entorno global (nivel de módulo) sin resúmenes: sirve como contexto para las funciones.
    module_pre = make("<module>", {}, {}, False)
    module_pre.run_body(tree.body)
    globals_env = dict(module_pre.env)

    # 1. Resúmenes hasta punto fijo
    summaries: dict[str, Summary] = {}
    for _ in range(MAX_FIXPOINT_ROUNDS):
        new: dict[str, Summary] = {}
        for name in sorted(called):
            fn = functions[name]
            params = _param_names(fn)
            a = make(name, summaries, globals_env, True)
            for i, p in enumerate(params):
                a.env[p] = Val((Taint(f"param:{i}", f"parámetro `{p}`", (TraceStep(fn.lineno, f"Parámetro `{p}` de `{name}()`"),)),), True)
            a.run_body(fn.body)
            new[name] = Summary(
                params=params,
                param_to_return=tuple(t for t in a.ret.taints if t.origin.startswith("param:")),
                returns_source=tuple(t for t in a.ret.taints if t.origin == "source"),
                return_unknown=a.ret.unknown,
                param_to_sink=tuple(sorted(set(a.param_sinks), key=lambda s: (s.location.line, s.location.col, s.param, s.kind))),
            )
        if new == summaries:
            break
        summaries = new

    # 2. Pasada final con fuentes reales
    result = TaintResult(summaries=summaries)
    analyzers = [make("<module>", summaries, {}, False)]
    analyzers[0].run_body(tree.body)
    module_env = dict(analyzers[0].env)
    for name, fn in functions.items():
        a = make(name, summaries, module_env, False)
        for p in _param_names(fn):
            a.env[p] = UNKNOWN
        a.run_body(fn.body)
        analyzers.append(a)

    seen_flows: set[tuple] = set()
    seen_sinks: set[tuple] = set()
    for a in analyzers:
        for f in a.flows:
            key = (f.kind, f.location, f.source)
            if key not in seen_flows:
                seen_flows.add(key)
                result.flows.setdefault(f.kind, []).append(f)
        for s in a.sinks:
            key = (s.kind, s.location)
            if key not in seen_sinks:
                seen_sinks.add(key)
                result.sinks.append(s)
    for flows in result.flows.values():
        flows.sort(key=lambda f: (f.location.line, f.location.col, f.source))
    result.sinks.sort(key=lambda s: (s.location.line, s.location.col, s.kind))
    return result
