import os

import requests


def cobrar(monto):
    cabeceras = {"Authorization": "Bearer " + os.environ["PAGOS_TOKEN"]}
    return requests.post("https://pagos.example/cobros", headers=cabeceras, json={"monto": monto}, timeout=10)
