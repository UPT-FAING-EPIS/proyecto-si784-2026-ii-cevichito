"""Las dependencias y el código minificado no se analizan, venga de donde venga el archivo."""

from sast.engine.runner import Engine, is_third_party

VULN_JS = 'document.getElementById("x").innerHTML = location.hash;\n'


def test_paths_of_dependencies_and_minified_names_are_third_party():
    for path in ("node_modules/x/index.js", "app/vendor/lib.php", "static/js/jquery-3.2.1.min.js",
                 "web/app.bundle.js", "pkg.egg-info/x.py", "third_party/a.py"):
        assert is_third_party(path), path
    for path in ("src/app.js", "vendors.py", "app/views.py", "minimal.js"):
        assert not is_third_party(path), path


def test_minified_content_is_detected_even_without_min_in_name():
    minified = "var a=1;" * 600  # una sola línea de ~4800 caracteres
    assert is_third_party("static/js/materialize.js", minified)
    assert not is_third_party("snippet.js", VULN_JS)                     # fragmento corto: nunca
    assert not is_third_party("src/app.js", "x = 1;\n" * 2000)           # código normal largo


def test_scan_files_skips_third_party_like_the_cli():
    report = Engine().scan_files([
        ("src/app.js", VULN_JS),
        ("node_modules/lib/index.js", VULN_JS),
        ("static/jquery.min.js", VULN_JS),
    ])
    assert report.files_scanned == 1
    assert {f.path for f in report.findings} == {"src/app.js"}


def test_tests_are_excluded_from_archives_but_not_from_a_named_file():
    secret = 'PASSWORD = "Sup3rS3creta!2024"\n'
    files = [("app/config.py", secret), ("tests/test_login.py", secret), ("app/test_utils.py", secret),
             ("test/security/profile.js", 'const password = "Sup3rS3creta!2024";\n'), ("web/__tests__/a.js", secret)]
    assert {f.path for f in Engine().scan_files(files).findings} == {"app/config.py"}
    assert Engine().scan_source(secret, path="test_login.py").findings  # fragmento pegado: siempre se analiza
