import base64
import json

from flask import Flask, request

app = Flask(__name__)


@app.route("/preferencias")
def preferencias():
    try:
        datos = json.loads(base64.b64decode(request.cookies.get("prefs", "")))
    except ValueError:
        datos = {}
    if not isinstance(datos, dict):
        datos = {}
    return {"tema": datos.get("tema", "claro")}
