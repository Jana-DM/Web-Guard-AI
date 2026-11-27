from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

EXCLUDED_DIR_NAMES = {
    "node_modules",
    ".git",
    "dist",
    "build",
    "coverage",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".next",
    ".nuxt",
    ".output",
    ".turbo",
    ".cache",
    ".parcel-cache",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".idea",
    ".vscode",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff", ".tif", ".heic", ".avif", ".psd", ".raw",
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".flv", ".m4v", ".3gp",
    ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pyc", ".pyo", ".pyd", ".class", ".jar",
}

LARGE_GENERATED_MAX_BYTES = 2 * 1024 * 1024  # 2 MB for bundle/minified files

WEB_EXTENSIONS = {
    ".html", ".htm",
    ".css", ".scss", ".sass", ".less",
    ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx",
    ".py",
    ".php",
    ".vue",
    ".svelte",
    ".astro",
    ".ejs", ".hbs", ".pug",
    ".jsp", ".asp", ".aspx",
    ".java",
    ".go",
    ".rb",
    ".sql",
    ".graphql", ".gql",
    ".json", ".yaml", ".yml", ".toml", ".xml",
}

WEB_CONFIG_FILES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "vite.config.js",
    "vite.config.ts",
    "vite.config.mjs",
    "vite.config.cjs",
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "tsconfig.json",
    "jsconfig.json",
    "angular.json",
    "vue.config.js",
    "svelte.config.js",
    "astro.config.mjs",
    "tailwind.config.js",
    "tailwind.config.ts",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".gitignore",
    ".env",
}


@dataclass
class FileInventory:
    total_discovered: int = 0
    total_scanned: int = 0
    total_excluded: int = 0
    scannable_files: list[Path] = field(default_factory=list)
    excluded_summary: dict[str, int] = field(default_factory=dict)
    all_discovered_relative: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_discovered": self.total_discovered,
            "total_scanned": self.total_scanned,
            "total_excluded": self.total_excluded,
            "excluded_breakdown": self.excluded_summary,
        }


@dataclass
class TechnologyValidationResult:
    is_valid: bool
    status: str  # "VALIDATED" or "FAILED"
    project_name: str
    detected_frameworks: list[str] = field(default_factory=list)
    detected_backend: list[str] = field(default_factory=list)
    detected_languages: list[str] = field(default_factory=list)
    detected_tools: list[str] = field(default_factory=list)
    failure_reasons: list[str] = field(default_factory=list)
    inventory: FileInventory = field(default_factory=FileInventory)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "is_valid": self.is_valid,
            "project_name": self.project_name,
            "detected_frameworks": self.detected_frameworks,
            "detected_backend": self.detected_backend,
            "detected_languages": self.detected_languages,
            "detected_tools": self.detected_tools,
            "failure_reasons": self.failure_reasons,
            "inventory": self.inventory.to_dict(),
        }


def build_project_inventory(workspace: Path) -> FileInventory:
    """
    Recursively inspect all files and directories in workspace.
    Intelligently identifies scannable files while recording and categorizing excluded items
    (e.g., node_modules, .git, dist, build, coverage, binaries, large generated bundles).
    Never skips .env or other hidden configuration files.
    """
    inventory = FileInventory()
    root = workspace.resolve()

    for current_root, dirs, files in os.walk(root):
        cur_path = Path(current_root)
        rel_dir = cur_path.relative_to(root).as_posix()

        # Track directory exclusions
        kept_dirs: list[str] = []
        for d in dirs:
            if d in EXCLUDED_DIR_NAMES:
                inventory.total_discovered += 1
                inventory.total_excluded += 1
                inventory.excluded_summary[d] = inventory.excluded_summary.get(d, 0) + 1
            else:
                kept_dirs.append(d)
        dirs[:] = kept_dirs

        for fname in files:
            fpath = cur_path / fname
            rel_file = fpath.relative_to(root).as_posix()
            inventory.total_discovered += 1
            inventory.all_discovered_relative.append(rel_file)

            ext = fpath.suffix.lower()
            low_name = fname.lower()

            # 1. Check if binary
            if ext in BINARY_EXTENSIONS:
                inventory.total_excluded += 1
                inventory.excluded_summary["binary_media"] = inventory.excluded_summary.get("binary_media", 0) + 1
                continue

            # 2. Check if large minified bundle (> 2MB)
            try:
                size = fpath.stat().st_size
                if size > LARGE_GENERATED_MAX_BYTES and (".min." in low_name or "bundle" in low_name or "chunk" in low_name):
                    inventory.total_excluded += 1
                    inventory.excluded_summary["large_generated_bundles"] = inventory.excluded_summary.get("large_generated_bundles", 0) + 1
                    continue
            except OSError:
                continue

            # 3. Always include .env, config files, and supported web source files
            if low_name == ".env" or low_name.startswith(".env."):
                inventory.scannable_files.append(fpath)
                inventory.total_scanned += 1
            elif low_name in WEB_CONFIG_FILES or ext in WEB_EXTENSIONS or low_name == ".gitignore":
                inventory.scannable_files.append(fpath)
                inventory.total_scanned += 1
            else:
                inventory.total_excluded += 1
                inventory.excluded_summary["unsupported_extensions"] = inventory.excluded_summary.get("unsupported_extensions", 0) + 1

    return inventory


def validate_web_project(workspace: Path, inventory: FileInventory | None = None) -> TechnologyValidationResult:
    """
    Validate whether the uploaded folder is a valid web development project.
    Validates actual file contents and project configuration files across:
    - Frontend languages: HTML, CSS, JavaScript, TypeScript, JSX, TSX
    - Frontend frameworks: React, Vite, Next.js, Angular, Vue.js, Svelte, Astro
    - Backend technologies: Node.js, Express.js, Python (FastAPI/Django/Flask), PHP, Java (Spring), Go, Ruby
    - Build/Dev Tools: Vite, Webpack, Tailwind, Docker
    """
    if inventory is None:
        inventory = build_project_inventory(workspace)

    root = workspace.resolve()
    detected_frameworks = set()
    detected_backend = set()
    detected_languages = set()
    detected_tools = set()

    project_name = root.name
    package_json_path = None

    # Inspect all scannable files
    for fpath in inventory.scannable_files:
        rel_posix = fpath.relative_to(root).as_posix()
        fname = fpath.name.lower()
        ext = fpath.suffix.lower()

        # Language Detection by extension & content
        if ext in {".html", ".htm"}:
            detected_languages.add("HTML")
        elif ext in {".css", ".scss", ".sass", ".less"}:
            detected_languages.add("CSS")
        elif ext in {".js", ".mjs", ".cjs"}:
            detected_languages.add("JavaScript")
        elif ext in {".jsx"}:
            detected_languages.add("JavaScript")
            detected_languages.add("JSX")
            detected_frameworks.add("React")
        elif ext in {".ts"}:
            detected_languages.add("TypeScript")
        elif ext in {".tsx"}:
            detected_languages.add("TypeScript")
            detected_languages.add("TSX")
            detected_frameworks.add("React")
        elif ext == ".py":
            detected_languages.add("Python")
            detected_backend.add("Python")
        elif ext == ".php":
            detected_languages.add("PHP")
            detected_backend.add("PHP")
        elif ext == ".java":
            detected_languages.add("Java")
            detected_backend.add("Java")
        elif ext == ".vue":
            detected_languages.add("Vue")
            detected_frameworks.add("Vue.js")
        elif ext == ".svelte":
            detected_languages.add("Svelte")
            detected_frameworks.add("Svelte")
        elif ext == ".astro":
            detected_languages.add("Astro")
            detected_frameworks.add("Astro")

        # Config files inspection
        if fname == "package.json":
            package_json_path = fpath
            detected_backend.add("Node.js")
            try:
                data = json.loads(fpath.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(data, dict):
                    if data.get("name") and isinstance(data["name"], str):
                        project_name = data["name"]
                    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    if "react" in deps or "react-dom" in deps:
                        detected_frameworks.add("React")
                    if "vite" in deps:
                        detected_frameworks.add("Vite")
                        detected_tools.add("Vite")
                    if "next" in deps:
                        detected_frameworks.add("Next.js")
                        detected_frameworks.add("React")
                    if "@angular/core" in deps:
                        detected_frameworks.add("Angular")
                    if "vue" in deps:
                        detected_frameworks.add("Vue.js")
                    if "svelte" in deps:
                        detected_frameworks.add("Svelte")
                    if "express" in deps:
                        detected_backend.add("Express.js")
                    if "fastify" in deps:
                        detected_backend.add("Fastify")
                    if "tailwindcss" in deps:
                        detected_tools.add("Tailwind CSS")
            except Exception:
                pass

        elif fname.startswith("vite.config."):
            detected_frameworks.add("Vite")
            detected_tools.add("Vite")
        elif fname.startswith("next.config."):
            detected_frameworks.add("Next.js")
            detected_frameworks.add("React")
        elif fname == "angular.json":
            detected_frameworks.add("Angular")
        elif fname == "vue.config.js":
            detected_frameworks.add("Vue.js")
        elif fname == "svelte.config.js":
            detected_frameworks.add("Svelte")
        elif fname in {"requirements.txt", "pyproject.toml", "pipfile"}:
            detected_languages.add("Python")
            detected_backend.add("Python")
            try:
                txt = fpath.read_text(encoding="utf-8", errors="ignore").lower()
                if "fastapi" in txt:
                    detected_backend.add("FastAPI")
                if "django" in txt:
                    detected_backend.add("Django")
                if "flask" in txt:
                    detected_backend.add("Flask")
            except Exception:
                pass
        elif fname == "composer.json":
            detected_languages.add("PHP")
            detected_backend.add("PHP")
            try:
                txt = fpath.read_text(encoding="utf-8", errors="ignore").lower()
                if "laravel" in txt:
                    detected_backend.add("Laravel")
            except Exception:
                pass
        elif fname in {"pom.xml", "build.gradle"}:
            detected_languages.add("Java")
            detected_backend.add("Java")
            try:
                txt = fpath.read_text(encoding="utf-8", errors="ignore").lower()
                if "spring" in txt:
                    detected_backend.add("Spring Boot")
            except Exception:
                pass

        # Code content inspection for framework imports & patterns (first 8KB)
        if ext in {".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".html"}:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    sample = f.read(8192)
                    if "from 'react'" in sample or 'from "react"' in sample or "React." in sample:
                        detected_frameworks.add("React")
                    if "from 'vue'" in sample or 'from "vue"' in sample:
                        detected_frameworks.add("Vue.js")
                    if "from 'next/" in sample or 'from "next/' in sample:
                        detected_frameworks.add("Next.js")
                    if "@angular/" in sample:
                        detected_frameworks.add("Angular")
                    if "express()" in sample or "require('express')" in sample:
                        detected_backend.add("Express.js")
                    if "from fastapi import" in sample or "FastAPI(" in sample:
                        detected_backend.add("FastAPI")
                    if "from flask import" in sample or "Flask(__name__)" in sample:
                        detected_backend.add("Flask")
                    if "django.http" in sample or "django.shortcuts" in sample:
                        detected_backend.add("Django")
                    if "<!DOCTYPE html" in sample or "<html" in sample:
                        detected_languages.add("HTML")
            except OSError:
                pass

    has_web_lang = len(detected_languages.intersection({"HTML", "CSS", "JavaScript", "TypeScript", "JSX", "TSX", "Python", "PHP", "Java", "Vue", "Svelte", "Astro"})) > 0
    has_web_framework = len(detected_frameworks) > 0
    has_web_backend = len(detected_backend) > 0
    has_web_config = package_json_path is not None or any(fname in WEB_CONFIG_FILES for fname in [p.name.lower() for p in inventory.scannable_files])

    is_valid = has_web_lang or has_web_framework or has_web_backend or has_web_config
    failure_reasons: list[str] = []

    if not is_valid:
        if inventory.total_discovered == 0:
            failure_reasons.append("Uploaded folder is completely empty.")
        else:
            media_count = inventory.excluded_summary.get("binary_media", 0)
            other_count = inventory.excluded_summary.get("unsupported_extensions", 0)
            if media_count > 0 and inventory.total_scanned == 0:
                failure_reasons.append(f"Folder contains only media/binary files ({media_count} detected) and no web code.")
            else:
                failure_reasons.append("No supported web frontend languages (HTML, CSS, JS, TS), backend technologies (Node, Python, PHP, Java), or web configurations were detected.")

    status = "VALIDATED" if is_valid else "FAILED"

    return TechnologyValidationResult(
        is_valid=is_valid,
        status=status,
        project_name=project_name,
        detected_frameworks=sorted(detected_frameworks),
        detected_backend=sorted(detected_backend),
        detected_languages=sorted(detected_languages),
        detected_tools=sorted(detected_tools),
        failure_reasons=failure_reasons,
        inventory=inventory,
    )
