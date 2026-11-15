import ast
import operator

from flask import Flask, abort, request

app = Flask(__name__)
OPERACIONES = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}


def _valor(nodo):
    if isinstance(nodo, ast.Constant) and isinstance(nodo.value, (int, float)):
        return nodo.value
    if isinstance(nodo, ast.BinOp) and type(nodo.op) in OPERACIONES:
        return OPERACIONES[type(nodo.op)](_valor(nodo.left), _valor(nodo.right))
    raise ValueError("expresión no permitida")


@app.route("/calcular")
def calcular():
    expresion = request.args.get("expr", "")
    try:
        return {"resultado": _valor(ast.parse(expresion, mode="eval").body)}
    except (SyntaxError, ValueError, ZeroDivisionError):
        abort(400)
