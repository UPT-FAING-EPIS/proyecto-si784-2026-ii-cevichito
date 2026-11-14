import html
from flask import request, render_template_string


def saludo():
    nombre = request.args.get("n")
    # Regresión: el motor heredado no lo detectaba (docs/baseline-f0.md).
    # ruleid: py/xss
    return render_template_string("<h1>Hola " + nombre + "</h1>")


def saludo_seguro():
    nombre = html.escape(request.args.get("n"))
    # ok: py/xss
    return render_template_string("<h1>Hola " + nombre + "</h1>")
