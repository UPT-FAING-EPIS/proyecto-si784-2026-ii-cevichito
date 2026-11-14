import os
import shlex
import subprocess
from flask import request


def directo():
    cmd = request.args.get("c")
    # ruleid: py/command-injection
    os.system("ls " + cmd)


def saneado():
    cmd = request.args.get("c")
    # ok: py/command-injection
    os.system("ls " + shlex.quote(cmd))


def helper(valor):
    # Caso de regresión (fallaba en el motor heredado): el flujo entre funciones no se detecta como inyección.
    # ruleid: py/command-injection
    os.system("ping -c 1 " + valor)


def entre_funciones():
    helper(request.args.get("host"))


def con_shell(host):
    # ruleid: py/command-injection
    subprocess.run("ping " + host, shell=True)


def sin_shell(host):
    # ok: py/command-injection
    subprocess.run(["ping", "-c", "1", host])
