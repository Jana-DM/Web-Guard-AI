from __future__ import annotations

from pathlib import Path


EXTENSION_LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".vue": "javascript",
    ".svelte": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".html": "html",
    ".htm": "html",
    ".ejs": "html",
    ".hbs": "html",
    ".pug": "html",
    ".css": "css",
    ".scss": "css",
    ".sass": "css",
    ".less": "css",
    ".php": "php",
    ".sql": "sql",
}

MANIFEST_FILES = {
    "requirements.txt": "python_manifest",
    "pyproject.toml": "python_manifest",
    "package.json": "node_manifest",
    "package-lock.json": "node_manifest",
    "composer.json": "php_manifest",
}


def detect_file_kind(path: Path) -> str:
    if path.name.lower() in MANIFEST_FILES:
        return MANIFEST_FILES[path.name.lower()]
    return EXTENSION_LANGUAGE_MAP.get(path.suffix.lower(), "other")


def summarize_languages(files: list[Path]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in files:
        kind = detect_file_kind(f)
        counts[kind] = counts.get(kind, 0) + 1
    return counts
