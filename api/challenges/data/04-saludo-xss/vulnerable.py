from flask import Flask, make_response, request

app = Flask(__name__)


@app.route("/saludo")
def saludo():
    nombre = request.args.get("nombre", "")
    return make_response("<h1>Hola, " + nombre + "</h1>")
