"""Pruebas unitarias de la huella estable `sastfp/v1`.

Escritas a partir del reporte de mutación: cada prueba fija una regla exacta del cálculo que
antes podía cambiarse sin que ninguna prueba fallara (ventana de líneas, normalización de
rutas y secretos, contador de ocurrencias y formato de la huella).
"""

from __future__ import annotations

import hashlib

import pytest

from sast.engine.fingerprint import (
    assign_fingerprints,
    line_hash,
    normalize_code,
    normalize_path,
    snippet_hash,
)
from sast.rules.api import Confidence, Finding, Severity


def hallazgo(line: int, *, end_line: int | None = None, rule_id: str = "py/sql-injection", path: str = "app.py",
             col: int = 0) -> Finding:
    return Finding(rule_id=rule_id, path=path, line=line, col=col, end_line=end_line or line, end_col=0,
                   message="m", severity=Severity.HIGH, confidence=Confidence.HIGH)


def sha(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


# --- normalize_path -----------------------------------------------------------------------------

@pytest.mark.parametrize(("ruta", "esperada"), [
    ("/src/app.py", "src/app.py"),          # barra inicial fuera
    ("//src/app.py", "src/app.py"),
    ("./src/app.py", "src/app.py"),
    ("././src/app.py", "src/app.py"),
    ("src\\app.py", "src/app.py"),          # rutas de Windows
    ("src/carpeta/", "src/carpeta/"),       # la barra final se conserva
    ("x/app.py", "x/app.py"),               # no se recortan letras
    ("owner-repo-1a2b3c4/src/app.py", "src/app.py"),   # prefijo del zipball de GitHub
])
def test_normalize_path(ruta, esperada):
    assert normalize_path(ruta) == esperada


# --- normalize_code -----------------------------------------------------------------------------

LINEAS = [f"linea_numero_{i} = {i}\n" for i in range(1, 11)]   # cada línea tiene > 12 caracteres útiles


def test_ventana_de_tres_lineas_como_maximo():
    assert normalize_code(LINEAS, 2, 9, "r") == "linea_numero_2=2linea_numero_3=3linea_numero_4=4"


def test_una_sola_linea_si_el_hallazgo_es_de_una_linea():
    assert normalize_code(LINEAS, 5, 5, "r") == "linea_numero_5=5"


def test_ventana_de_dos_lineas():
    assert normalize_code(LINEAS, 5, 6, "r") == "linea_numero_5=5linea_numero_6=6"


def test_la_linea_0_se_trata_como_la_1():
    assert normalize_code(LINEAS, 0, 0, "r") == "linea_numero_1=1"
    assert normalize_code(LINEAS, 1, 1, "r") == "linea_numero_1=1"


def test_no_pasa_del_final_del_archivo():
    assert normalize_code(LINEAS, 10, 12, "r") == "linea_numero_10=10"


def test_sin_codigo_fuente_la_normalizacion_es_vacia():
    assert normalize_code([], 3, 3, "r") == ""


def test_una_linea_corta_se_completa_con_la_siguiente():
    lineas = ["x = 1\n", "y = funcion_larga()\n", "z = 3\n"]
    assert normalize_code(lineas, 1, 1, "r") == "x=1y=funcion_larga()"


def test_linea_de_exactamente_12_caracteres_no_se_completa():
    lineas = ["abcdefghijkl\n", "siguiente_linea\n"]
    assert normalize_code(lineas, 1, 1, "r") == "abcdefghijkl"


def test_linea_de_11_caracteres_si_se_completa():
    lineas = ["abcdefghijk\n", "siguiente\n"]
    assert normalize_code(lineas, 1, 1, "r") == "abcdefghijksiguiente"


def test_secretos_se_enmascaran_solo_en_la_regla_de_secretos():
    lineas = ['API_KEY = "abc123secretisimo"\n']
    assert normalize_code(lineas, 1, 1, "generic/hardcoded-secret") == 'API_KEY="S"'
    assert normalize_code(lineas, 1, 1, "py/sql-injection") == 'API_KEY="abc123secretisimo"'


def test_cambiar_el_secreto_no_cambia_la_huella():
    a = [hallazgo(1, rule_id="generic/hardcoded-secret")]
    h1 = assign_fingerprints(a, {"app.py": ['TOKEN = "viejo-0000000000"\n']})[0].fingerprint
    h2 = assign_fingerprints(a, {"app.py": ['TOKEN = "nuevo-1111111111"\n']})[0].fingerprint
    assert h1 == h2


# --- line_hash ------------------------------------------------------------------------------------

def test_line_hash_usa_la_linea_pedida_sin_espacios():
    lineas = ["a = 1\n", "b  =  2\n", "c = 3\n"]
    assert line_hash(lineas, 1) == sha("a=1")
    assert line_hash(lineas, 2) == sha("b=2")
    assert line_hash(lineas, 3) == sha("c=3")


@pytest.mark.parametrize("linea", [0, 4, -1])
def test_line_hash_fuera_de_rango_es_el_hash_vacio(linea):
    assert line_hash(["a = 1\n", "b = 2\n", "c = 3\n"], linea) == sha("")


# --- snippet_hash y assign_fingerprints ----------------------------------------------------------

def test_snippet_hash_depende_de_la_regla_para_los_secretos():
    lineas = ['clave = "muy-secreta-123"\n']
    secreto = snippet_hash(lineas, hallazgo(1, rule_id="generic/hardcoded-secret"))
    assert secreto == sha('clave="S"')


def test_formato_exacto_de_la_huella():
    lineas = ["cur.execute(consulta_insegura)\n"]
    f = assign_fingerprints([hallazgo(1, path="./src/app.py")], {"./src/app.py": lineas})[0]
    s_hash = sha("cur.execute(consulta_insegura)")
    assert f.fingerprint == sha(f"v1|sast-studio|py/sql-injection|src/app.py|{s_hash}|1")


def test_la_huella_sobrevive_a_un_cambio_de_linea():
    antes = ["cur.execute(consulta_insegura)\n"]
    despues = ["# comentario nuevo\n", "\n", "cur.execute(consulta_insegura)\n"]
    h1 = assign_fingerprints([hallazgo(1)], {"app.py": antes})[0].fingerprint
    h2 = assign_fingerprints([hallazgo(3)], {"app.py": despues})[0].fingerprint
    assert h1 == h2


def test_dos_hallazgos_iguales_tienen_huellas_distintas_y_estables():
    lineas = ["cur.execute(consulta_insegura)\n"] * 2
    f1, f2 = assign_fingerprints([hallazgo(2), hallazgo(1)], {"app.py": lineas})
    s_hash = sha("cur.execute(consulta_insegura)")
    assert (f1.line, f2.line) == (1, 2)   # orden estable por línea
    assert f1.fingerprint == sha(f"v1|sast-studio|py/sql-injection|app.py|{s_hash}|1")
    assert f2.fingerprint == sha(f"v1|sast-studio|py/sql-injection|app.py|{s_hash}|2")


def test_otra_ruta_u_otra_regla_cambian_la_huella():
    lineas = {"a.py": ["cur.execute(consulta_insegura)\n"], "b.py": ["cur.execute(consulta_insegura)\n"]}
    base = assign_fingerprints([hallazgo(1, path="a.py")], lineas)[0].fingerprint
    assert assign_fingerprints([hallazgo(1, path="b.py")], lineas)[0].fingerprint != base
    assert assign_fingerprints([hallazgo(1, path="a.py", rule_id="py/xss")], lineas)[0].fingerprint != base


def test_sin_codigo_fuente_tambien_hay_huella():
    f = assign_fingerprints([hallazgo(4, path="falta.py")], {})[0]
    assert f.fingerprint == sha(f"v1|sast-studio|py/sql-injection|falta.py|{sha('')}|1")
