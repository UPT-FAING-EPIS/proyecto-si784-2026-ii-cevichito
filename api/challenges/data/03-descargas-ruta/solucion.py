from flask import Flask, request, send_from_directory

app = Flask(__name__)
BASE = "/srv/entregas"


@app.route("/descargar")
def descargar():
    nombre = request.args.get("archivo", "")
    return send_from_directory(BASE, nombre)
