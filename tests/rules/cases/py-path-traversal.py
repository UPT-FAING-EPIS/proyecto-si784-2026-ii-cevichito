import os
from flask import request, send_file, send_from_directory


def descargar():
    name = request.args.get("f")
    # Regresión: el motor heredado no lo detectaba (docs/baseline-f0.md).
    # ruleid: py/path-traversal
    return open("/srv/files/" + name).read()


def descargar_seguro():
    name = os.path.basename(request.args.get("f"))
    # ok: py/path-traversal
    return send_file(os.path.join("/srv/files", name))


def descargar_con_flask():
    name = request.args.get("f")
    # send_from_directory aplica safe_join: rechaza nombres que salgan del directorio.
    # ok: py/path-traversal
    return send_from_directory("/srv/files", name)
