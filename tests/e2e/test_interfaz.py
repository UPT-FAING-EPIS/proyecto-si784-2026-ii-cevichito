"""Pruebas de interfaz de usuario: un navegador real (Chromium con Playwright) usando la web.

Cada prueba sigue el recorrido de un usuario por las pantallas, como en la demostración, y
guarda una captura del estado final en el reporte HTML.
"""

from __future__ import annotations

import re
import uuid

import pytest

# Playwright es una herramienta de requirements-pruebas.txt: sin ella, el módulo se omite.
pytest.importorskip("playwright")
from playwright.sync_api import Page, expect  # noqa: E402

from api import challenges

pytestmark = pytest.mark.ui

VULNERABLE = (
    "import sqlite3\n"
    "from flask import request\n\n\n"
    "def buscar():\n"
    '    nombre = request.args["nombre"]\n'
    '    db = sqlite3.connect("app.db")\n'
    "    return db.execute(\"SELECT * FROM usuarios WHERE nombre = '%s'\" % nombre).fetchall()\n"
)


def entrar(page: Page, servidor: str) -> str:
    """Entra con el acceso de desarrollo y devuelve el correo usado."""
    email = f"ui-{uuid.uuid4().hex[:8]}@pruebas.test"
    page.goto(f"{servidor}/login")
    page.get_by_label("Correo").fill(email)
    page.get_by_role("button", name="Entrar").click()
    expect(page.get_by_role("heading", name="Proyectos", exact=True)).to_be_visible()
    return email


def escribir_en_editor(page: Page, codigo: str) -> None:
    """Sustituye el contenido del editor CodeMirror como lo haría el usuario (pegar)."""
    editor = page.locator(".cm-content").first
    editor.click()
    page.keyboard.press("Control+A")
    page.keyboard.press("Delete")
    page.keyboard.insert_text(codigo)


def test_la_pantalla_de_inicio_no_deja_entrar_sin_correo(page: Page, servidor):
    # El servidor de pruebas no configura Google: solo muestra el acceso de desarrollo.
    page.goto(f"{servidor}/login")
    expect(page.get_by_role("heading", name="Inicia sesión")).to_be_visible()
    expect(page.get_by_role("button", name="Entrar")).to_be_disabled()
    page.get_by_label("Correo").fill("sin-arroba")
    expect(page.get_by_role("button", name="Entrar")).to_be_disabled()
    page.get_by_label("Correo").fill("ana@pruebas.test")
    expect(page.get_by_role("button", name="Entrar")).to_be_enabled()


def test_sin_sesion_redirige_al_inicio(page: Page, servidor):
    page.goto(f"{servidor}/proyectos")
    expect(page).to_have_url(re.compile(r"/login"))


def test_escanear_codigo_pegado_y_leer_el_hallazgo_explicado(page: Page, servidor):
    entrar(page, servidor)
    page.get_by_role("button", name="Nuevo proyecto").first.click()
    page.get_by_label("Nombre").fill("practica-ui")
    page.get_by_role("button", name="Crear").click()

    # Al crear el proyecto, la web lleva directamente a «Nuevo escaneo».
    expect(page.get_by_role("heading", name="Nuevo escaneo")).to_be_visible()
    escribir_en_editor(page, VULNERABLE)
    page.get_by_role("button", name="Lanzar escaneo").click()

    hallazgo = page.get_by_role("row").filter(has_text="py/sql-injection").first
    expect(hallazgo).to_be_visible(timeout=60_000)
    expect(hallazgo).to_contain_text("Crítica")
    hallazgo.click()

    expect(page.get_by_role("heading", name="Qué ocurre")).to_be_visible()
    expect(page.get_by_role("heading", name="Cómo corregirlo")).to_be_visible()
    expect(page.get_by_text("CWE-89").first).to_be_visible()


def test_reto_de_correccion_en_el_editor_del_navegador(page: Page, servidor):
    reto = challenges.get("01-login-sql")
    entrar(page, servidor)
    page.get_by_role("link", name="Retos").first.click()
    total = len(challenges.catalog())
    expect(page.get_by_text(f"Superados 0 de {total}")).to_be_visible()

    page.get_by_role("link", name=re.compile(reto.title)).first.click()
    page.get_by_role("button", name="Comprobar").click()
    expect(page.get_by_text("La vulnerabilidad sigue presente")).to_be_visible(timeout=60_000)

    escribir_en_editor(page, reto.solution)
    page.get_by_role("button", name="Comprobar").click()
    expect(page.get_by_text("¡Reto superado!")).to_be_visible(timeout=60_000)


def test_las_pistas_aparecen_de_una_en_una(page: Page, servidor):
    reto = challenges.get("01-login-sql")
    entrar(page, servidor)
    page.goto(f"{servidor}/retos/{reto.id}")
    pistas = page.get_by_role("region", name="Pistas").get_by_role("listitem")
    expect(pistas).to_have_count(0)
    page.get_by_role("button", name=re.compile("Ver una pista")).click()
    expect(pistas).to_have_count(1)
    # La pista se muestra sin las comillas invertidas: el código va con formato de código.
    expect(pistas.first).to_contain_text(reto.hints[0].replace("`", ""))
    if len(reto.hints) > 1:
        page.get_by_role("button", name=re.compile("Ver otra pista")).click()
        expect(pistas).to_have_count(2)


def test_catalogo_de_reglas(page: Page, servidor):
    entrar(page, servidor)
    page.get_by_role("link", name="Reglas").first.click()
    expect(page.get_by_role("heading", name="Catálogo de reglas")).to_be_visible()
    expect(page.get_by_text("py/sql-injection").first).to_be_visible()


def test_en_movil_no_hay_desplazamiento_horizontal(page: Page, servidor):
    page.set_viewport_size({"width": 375, "height": 812})
    entrar(page, servidor)
    for ruta in ("/proyectos", "/retos", "/reglas"):
        page.goto(servidor + ruta)
        page.wait_for_load_state("networkidle")
        ancho = page.evaluate("document.documentElement.scrollWidth")
        assert ancho <= 375, f"{ruta}: {ancho}px de ancho en un móvil de 375px"
