"""Detección de lenguaje por extensión y prefijos de ID por lenguaje."""

from __future__ import annotations

from pathlib import PurePath

EXTENSIONS: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".html": "html", ".htm": "html", ".vue": "vue", ".svelte": "svelte",
    ".php": "php", ".phtml": "php",
    ".java": "java", ".kt": "kotlin",
    ".go": "go",
    ".rb": "ruby",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".cs": "csharp",
    ".sql": "sql",
    ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
    ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".xml": "xml", ".toml": "toml",
}

#: Lenguajes analizados con AST + taint. El resto, solo con reglas heurísticas.
AST_LANGUAGES = frozenset({"python"})

#: Grupos que pueden usarse en el campo `languages` de una regla.
GROUPS: dict[str, frozenset[str]] = {
    "any": frozenset(EXTENSIONS.values()) | {"config"},
    "web": frozenset({"javascript", "typescript", "html", "vue", "svelte", "php"}),
}


def detect_language(path: str) -> str | None:
    p = PurePath(path)
    name = p.name.lower()
    if name == ".env" or name.startswith(".env."):
        return "config"
    return EXTENSIONS.get(p.suffix.lower())


def language_matches(language: str, rule_languages: tuple[str, ...]) -> bool:
    for entry in rule_languages:
        if entry == language or language in GROUPS.get(entry, ()):
            return True
    return False


def comment_prefixes(language: str) -> tuple[str, ...]:
    if language in {"python", "shell", "ruby", "yaml", "toml", "config", "powershell"}:
        return ("#",)
    if language in {"sql"}:
        return ("--",)
    if language in {"html", "xml"}:
        return ("<!--",)
    if language == "php":
        return ("//", "#", "/*", "*")
    return ("//", "/*", "*")
