"""El cálculo del benchmark: categorías y puntuación (sin ejecutar Bandit ni Semgrep)."""

from sast.bench import Hit, ToolRun, category_of_cwes, score


def test_categories_from_cwe_strings():
    assert category_of_cwes(["CWE-89: SQL Injection"]) == "sqli"
    assert category_of_cwes(("CWE-327", "CWE-328")) == "crypto"
    assert category_of_cwes(["CWE-1"]) is None


def test_score_counts_hits_only_on_annotated_lines_of_the_same_category():
    truth = [("a.py", 10, "sqli", True), ("a.py", 20, "sqli", False), ("a.py", 30, "cmdi", True)]
    run = ToolRun("x", hits=[Hit("a.py", 9, 11, "sqli"),     # acierto (la línea 10 está en el rango)
                             Hit("a.py", 20, 20, "sqli"),    # falso positivo en una línea `ok`
                             Hit("a.py", 30, 30, "xss"),     # categoría equivocada: no cuenta
                             Hit("a.py", 99, 99, "sqli")])   # línea sin anotar: se ignora
    total = score(truth, run)["__total__"]
    assert (total.tp, total.fp, total.fn, total.tn) == (1, 1, 1, 0)
    assert total.precision == 0.5 and total.recall == 0.5
