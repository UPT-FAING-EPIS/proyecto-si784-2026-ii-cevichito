"""Pruebas unitarias de la lectura segura de ZIP (`api/services/archive.py`).

Escritas a partir del reporte de mutación: fijan los límites exactos (`>` frente a `>=`), el
código HTTP y el mensaje de cada error, y las rutas peligrosas que deben rechazarse.
"""

from __future__ import annotations

import io
import zipfile
from types import SimpleNamespace

import pytest

from api.services.archive import ENTRIES_FACTOR, ArchiveError, Limits, _safe_name, read_zip


def zip_de(entradas: dict[str, bytes], *, comprimir: bool = False) -> bytes:
    buf = io.BytesIO()
    modo = zipfile.ZIP_DEFLATED if comprimir else zipfile.ZIP_STORED
    with zipfile.ZipFile(buf, "w", modo) as z:
        for nombre, datos in entradas.items():
            z.writestr(nombre, datos)
    return buf.getvalue()


def error(data: bytes, **kw) -> ArchiveError:
    with pytest.raises(ArchiveError) as exc:
        read_zip(data, **kw)
    return exc.value


# --- Rutas --------------------------------------------------------------------------------------

@pytest.mark.parametrize(("nombre", "esperado"), [
    ("src/app.py", "src/app.py"),
    ("src\\app.py", "src/app.py"),
    ("src/./app.py", "src/app.py"),
    ("src/sub/../app.py", "src/app.py"),
    ("a", "a"),
    ("/etc/passwd", None),
    ("\\windows\\x.py", None),
    ("C:/x.py", None),
    ("c:x.py", None),
    ("c:", None),                 # unidad de Windows sin ruta
    ("..", None),
    ("../x.py", None),
    ("src/../../x.py", None),
    ("src\\..\\..\\x.py", None),
])
def test_safe_name(nombre, esperado):
    assert _safe_name(nombre) == esperado


# --- Errores: código, estado HTTP y mensaje -----------------------------------------------------

def test_zip_invalido():
    e = error(b"esto no es un zip")
    assert (e.code, e.status, e.message) == ("invalid_zip", 422, "El archivo no es un ZIP válido.")
    assert str(e) == "invalid_zip"


def test_ruta_insegura():
    e = error(zip_de({"../fuera.py": b"x = 1\n"}))
    assert (e.code, e.status, e.message) == ("unsafe_path", 422, "El ZIP contiene rutas absolutas o con '..'.")


def test_enlace_simbolico():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("enlace.py")
        info.external_attr = (0o120777 << 16)
        z.writestr(info, "/etc/passwd")
    e = error(buf.getvalue())
    assert (e.code, e.status, e.message) == ("symlink", 422, "El ZIP contiene enlaces simbólicos.")


def test_error_por_defecto_es_422():
    assert ArchiveError("x", "y").status == 422


# --- Límites exactos ----------------------------------------------------------------------------

def test_entradas_totales_justo_en_el_limite_se_aceptan():
    limites = Limits(max_entries=1)
    entradas = {f"doc{i}.txt": b"" for i in range(ENTRIES_FACTOR)}
    assert read_zip(zip_de(entradas), limites).files == []


def test_una_entrada_de_mas_se_rechaza():
    limites = Limits(max_entries=1)
    entradas = {f"doc{i}.txt": b"" for i in range(ENTRIES_FACTOR + 1)}
    e = error(zip_de(entradas), limits=limites)
    assert (e.code, e.status) == ("too_many_entries", 413)
    assert e.message == f"El ZIP tiene más de {ENTRIES_FACTOR} entradas."


def test_archivos_de_codigo_justo_en_el_limite():
    limites = Limits(max_entries=2)
    assert len(read_zip(zip_de({"a.py": b"a = 1\n", "b.py": b"b = 2\n"}), limites).files) == 2
    e = error(zip_de({"a.py": b"a = 1\n", "b.py": b"b = 2\n", "c.py": b"c = 3\n"}), limits=limites)
    assert (e.code, e.status) == ("too_many_files", 413)
    assert e.message == "El código tiene más de 2 archivos analizables."


def test_total_descomprimido_justo_en_el_limite():
    limites = Limits(max_total_bytes=20)
    assert len(read_zip(zip_de({"a.py": b"x" * 10, "b.py": b"y" * 10}), limites).files) == 2
    e = error(zip_de({"a.py": b"x" * 10, "b.py": b"y" * 11}), limits=limites)
    assert (e.code, e.status, e.message) == ("too_large", 413, "El contenido descomprimido supera el límite total.")


def test_archivo_justo_en_el_tamano_maximo_se_conserva_y_uno_mas_se_omite():
    limites = Limits(max_entry_bytes=10)
    res = read_zip(zip_de({"ok.py": b"a" * 10, "grande.py": b"b" * 11}), limites)
    assert [n for n, _ in res.files] == ["ok.py"]
    assert res.skipped == [{"path": "grande.py", "reason": "archivo demasiado grande"}]


def test_bomba_zip_por_razon_de_compresion():
    e = error(zip_de({"bomba.py": b"0" * 2_000_000}, comprimir=True), limits=Limits(max_ratio=100))
    assert (e.code, e.status, e.message) == (
        "compression_ratio", 413, "Razón de compresión sospechosa (posible bomba ZIP).")


def test_contenido_utf8_se_decodifica():
    res = read_zip(zip_de({"a.py": "nombre = 'Ñandú'\n".encode()}))
    assert res.files == [("a.py", "nombre = 'Ñandú'\n")]


# --- Carpeta raíz -------------------------------------------------------------------------------

def test_por_defecto_no_se_quita_la_carpeta_raiz():
    res = read_zip(zip_de({"repo-main/a.py": b"a = 1\n"}))
    assert res.root_prefix == ""
    assert res.files[0][0] == "repo-main/a.py"


def test_con_strip_root_se_quita_la_carpeta_raiz_comun():
    res = read_zip(zip_de({"repo-main/a.py": b"a = 1\n", "repo-main/src/b.py": b"b = 2\n"}), strip_root=True)
    assert res.root_prefix == "repo-main/"
    assert sorted(n for n, _ in res.files) == ["a.py", "src/b.py"]


def test_sin_raiz_comun_no_se_quita_nada():
    res = read_zip(zip_de({"uno/a.py": b"a = 1\n", "dos/b.py": b"b = 2\n"}), strip_root=True)
    assert res.root_prefix == ""
    assert sorted(n for n, _ in res.files) == ["dos/b.py", "uno/a.py"]


# --- Configuración -----------------------------------------------------------------------------

def test_limites_desde_la_configuracion():
    s = SimpleNamespace(max_zip_entries=7, max_entry_mb=2, max_total_uncompressed_mb=3, max_compression_ratio=50)
    assert Limits.from_settings(s) == Limits(max_entries=7, max_entry_bytes=2 * 1024 * 1024,
                                             max_total_bytes=3 * 1024 * 1024, max_ratio=50)
