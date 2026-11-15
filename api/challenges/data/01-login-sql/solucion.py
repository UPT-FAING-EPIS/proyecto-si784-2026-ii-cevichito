import sqlite3

from flask import Flask, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("tienda.db")


@app.route("/login", methods=["POST"])
def login():
    usuario = request.form["usuario"]
    clave = request.form["clave"]
    db = get_db()
    fila = db.execute("SELECT id FROM usuarios WHERE nombre = ? AND clave = ?", (usuario, clave)).fetchone()
    if fila:
        return "Bienvenido"
    return "Credenciales incorrectas", 401
