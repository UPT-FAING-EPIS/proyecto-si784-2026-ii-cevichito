import requests
from flask import request


def proxy():
    url = request.args.get("url")
    # ruleid: py/ssrf
    return requests.get(url).text


def fijo():
    # ok: py/ssrf
    return requests.get("https://api.example.com/status").text
