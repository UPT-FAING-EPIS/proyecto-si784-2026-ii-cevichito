import base64
import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/preferencias")
def preferencias():
    datos = pickle.loads(base64.b64decode(request.cookies.get("prefs", "")))
    return {"tema": datos.get("tema", "claro")}
