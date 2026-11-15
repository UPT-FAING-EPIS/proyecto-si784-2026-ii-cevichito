import os

from flask import Flask, request, send_file

app = Flask(__name__)
BASE = "/srv/entregas"


@app.route("/descargar")
def descargar():
    nombre = request.args.get("archivo", "")
    ruta = os.path.join(BASE, nombre)
    return send_file(ruta)
