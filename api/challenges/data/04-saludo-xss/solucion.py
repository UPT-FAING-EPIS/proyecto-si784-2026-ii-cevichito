from flask import Flask, make_response, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/saludo")
def saludo():
    nombre = request.args.get("nombre", "")
    return make_response("<h1>Hola, " + escape(nombre) + "</h1>")
