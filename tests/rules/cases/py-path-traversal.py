import os
from flask import request, send_file


def descargar():
    name = request.args.get("f")
    # Regresión: el motor heredado no lo detectaba (docs/baseline-f0.md).
    # ruleid: py/path-traversal
    return open("/srv/files/" + name).read()


def descargar_seguro():
    name = os.path.basename(request.args.get("f"))
    # ok: py/path-traversal
    return send_file(os.path.join("/srv/files", name))
