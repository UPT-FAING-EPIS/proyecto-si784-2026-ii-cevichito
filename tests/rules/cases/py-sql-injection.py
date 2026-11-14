import sqlite3
from flask import request

conn = sqlite3.connect("app.db")
cur = conn.cursor()


def por_id():
    uid = request.args.get("id")
    # Regresión: el motor heredado no lo detectaba (docs/baseline-f0.md).
    # ruleid: py/sql-injection
    cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)


def parametrizada():
    uid = request.args.get("id")
    # ok: py/sql-injection
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))


def con_int():
    uid = int(request.args.get("id"))
    # ok: py/sql-injection
    cur.execute("SELECT * FROM users WHERE id = %d" % uid)


def por_nombre(name):
    # Regresión: el motor heredado no lo detectaba (docs/baseline-f0.md).
    # ruleid: py/sql-injection
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")


# --- La consulta se construye en una variable antes de execute() -------------------
# Caso real de anxolerd/dvpwa (sqli/dao/student.py): el dato viene de otro archivo,
# así que solo la variante heurística puede verlo.
async def crear_estudiante(conn, name):
    q = ("INSERT INTO students (name) "
         "VALUES ('%(name)s')" % {'name': name})
    async with conn.cursor() as cur:
        # ruleid: py/sql-injection
        await cur.execute(q)


def concatenada_por_partes(name):
    q = "SELECT * FROM users WHERE name = '"
    q += name + "'"
    # ruleid: py/sql-injection
    cur.execute(q)


async def limite_parametrizado(limit):
    q = "SELECT id, name FROM students"
    params = {}
    if limit is not None:
        q += " LIMIT %(limit)s"
        params["limit"] = limit
    # ok: py/sql-injection
    await cur.execute(q, params)


def variable_con_marcador(uid):
    q = "SELECT * FROM users WHERE id = %s"
    # ok: py/sql-injection
    cur.execute(q, (uid,))
