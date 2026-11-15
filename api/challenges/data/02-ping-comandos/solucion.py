import re
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)
HOST_VALIDO = re.compile(r"[A-Za-z0-9.-]{1,253}")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_VALIDO.fullmatch(host):
        abort(400)
    salida = subprocess.check_output(["ping", "-c", "1", host])
    return {"resultado": salida.decode()}
