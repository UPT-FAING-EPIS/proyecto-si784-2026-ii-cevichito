import requests

PAGOS_TOKEN = "f3a9c1e7b5d24068a1c3e5f7b9d1a3c5"


def cobrar(monto):
    cabeceras = {"Authorization": "Bearer " + PAGOS_TOKEN}
    return requests.post("https://pagos.example/cobros", headers=cabeceras, json={"monto": monto}, timeout=10)
