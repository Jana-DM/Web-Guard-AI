from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SENSITIVE_DIR_NAMES = {
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".gcp",
    ".kube",
    ".pki",
    "secrets",
    "private",
    "credentials",
    "certs",
    "ssl",
    "keys",
    "tokens",
}

SENSITIVE_EXACT_FILENAMES = {
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_dsa",
    "id_ecdsa",
    ".htpasswd",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".pgpass",
    "kubeconfig",
    "wallet.dat",
    "terraform.tfstate",
    "terraform.tfvars",
    "credentials.json",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    ".secrets",
    "vault.yml",
    "vault.yaml",
}

SENSITIVE_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".ppk",
    ".kdbx",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".bak",
    ".tfvars",
    ".tfstate",
}

WEB_CODE_EXTENSIONS = {
    ".html",
    ".htm",
    ".css",
    ".scss",
    ".sass",
    ".less",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".py",
    ".php",
    ".vue",
    ".svelte",
    ".astro",
    ".ejs",
    ".hbs",
    ".pug",
    ".jsp",
    ".asp",
    ".aspx",
    ".sql",
    ".graphql",
    ".gql",
}

WEB_MANIFEST_FILENAMES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "composer.json",
}

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tiff", ".tif", ".heic", ".avif", ".psd", ".raw", ".svg"}
VIDEO_EXTENSIONS = {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".flv", ".m4v", ".3gp"}
AUDIO_EXTENSIONS = {".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a", ".wma"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".rtf"}
IGNORED_TECH_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    ".next",
    "site-packages",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "coverage",
}

WEB_SNIPPET_REGEX = re.compile(
    r"<!doctype\s+html|<html\b|<script\b|<form\b|<\?php\b|<iframe\b|@import\s+url\(",
    re.IGNORECASE,
)


@dataclass
class ContentInspectionResult:
    web_files: list[Path] = field(default_factory=list)
    sensitive_detected: list[str] = field(default_factory=list)
    skipped_non_web: dict[str, int] = field(default_factory=dict)

    def add_non_web(self, category: str, count: int = 1) -> None:
        if count <= 0:
            return
        self.skipped_non_web[category] = self.skipped_non_web.get(category, 0) + count

    def merge_non_web(self, extra: dict[str, int] | None) -> None:
        if not extra:
            return
        for k, v in extra.items():
            self.add_non_web(k, int(v))

    def merge_sensitive(self, extra: list[str] | None) -> None:
        if not extra:
            return
        existing = set(self.sensitive_detected)
        for item in extra:
            clean = item.strip()
            if clean and clean not in existing:
                existing.add(clean)
                self.sensitive_detected.append(clean)


def is_sensitive_path(rel_path: str) -> tuple[bool, str | None]:
    """
    Determine by path/filename ONLY whether a file or directory is sensitive.
    NEVER reads file contents. Returns (is_sensitive, matched_label).
    """
    normalized = rel_path.replace("\\", "/").strip("/")
    if not normalized:
        return False, None

    parts = [p for p in normalized.split("/") if p and p != "."]
    if not parts:
        return False, None

    # Check directory segments first
    for idx, seg in enumerate(parts[:-1]):
        low = seg.lower()
        if low in SENSITIVE_DIR_NAMES:
            return True, "/".join(parts[: idx + 1]) + "/"

    filename = parts[-1]
    low_name = filename.lower()

    # Safe templates/examples are explicitly allowed
    if low_name.endswith((".example", ".sample", ".template")):
        return False, None

    if low_name in SENSITIVE_DIR_NAMES:
        return True, normalized + "/"

    if low_name == ".env" or low_name.startswith(".env."):
        return True, normalized

    if low_name in SENSITIVE_EXACT_FILENAMES:
        return True, normalized

    if ("service_account" in low_name or "service-account" in low_name) and low_name.endswith(".json"):
        return True, normalized

    _, ext = os.path.splitext(low_name)
    if ext in SENSITIVE_EXTENSIONS:
        return True, normalized

    return False, None


def classify_non_sensitive_filename(filename: str) -> str:
    """Classify a file purely by name/extension into web_code, txt, image, video, audio, document, or other."""
    low = Path(filename).name.lower()
    if low in WEB_MANIFEST_FILENAMES:
        return "web_code"
    _, ext = os.path.splitext(low)
    if ext in WEB_CODE_EXTENSIONS:
        return "web_code"
    if ext == ".txt":
        return "text"
    if ext in IMAGE_EXTENSIONS:
        return "images"
    if ext in VIDEO_EXTENSIONS:
        return "videos"
    if ext in AUDIO_EXTENSIONS:
        return "audio"
    if ext in DOCUMENT_EXTENSIONS:
        return "documents"
    if ext == ".json":
        return "config_json"
    return "other"


def _is_plain_text_non_web(file_path: Path) -> bool:
    """Inspect a non-sensitive .txt file snippet to distinguish web markup from plain text notes."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(16384)
    except OSError:
        return True
    return not bool(WEB_SNIPPET_REGEX.search(head))


def sanitize_workspace_sensitive_items(workspace: Path) -> list[str]:
    """
    Walk workspace by directory/file names ONLY (without reading contents),
    immediately delete any sensitive files or folders, and return their relative names.
    """
    detected: list[str] = []
    seen: set[str] = set()
    root = workspace.resolve()

    for current_root, dirs, files in os.walk(root, topdown=True):
        cur_path = Path(current_root)
        rel_dir = cur_path.relative_to(root).as_posix()

        kept_dirs: list[str] = []
        for d in dirs:
            if d in {".git", "node_modules", "__pycache__"} or d.startswith(".venv"):
                continue
            cand_rel = f"{rel_dir}/{d}/a" if rel_dir != "." else f"{d}/a"
            sens, label = is_sensitive_path(cand_rel)
            if sens and label:
                if label not in seen:
                    seen.add(label)
                    detected.append(label)
                shutil.rmtree(cur_path / d, ignore_errors=True)
            else:
                kept_dirs.append(d)
        dirs[:] = kept_dirs

        for fname in files:
            fpath = cur_path / fname
            rel_file = fpath.relative_to(root).as_posix()
            sens, label = is_sensitive_path(rel_file)
            if sens and label:
                if label not in seen:
                    seen.add(label)
                    detected.append(label)
                fpath.unlink(missing_ok=True)

    return detected


def validate_workspace_content(
    workspace: Path,
    pre_sensitive: list[str] | None = None,
    pre_non_web: dict[str, int] | None = None,
) -> ContentInspectionResult:
    """
    Inspect workspace after sensitive-item removal:
    - Separates valid web/code files from media/documents/plain text.
    - Rejects (cleaning up workspace) when zero valid web/code files are present.
    """
    result = ContentInspectionResult()
    result.merge_sensitive(sanitize_workspace_sensitive_items(workspace))
    result.merge_sensitive(pre_sensitive)
    result.merge_non_web(pre_non_web)

    root = workspace.resolve()
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [
            d for d in dirs
            if d not in IGNORED_TECH_DIRS and not d.startswith(".venv") and not d.startswith("venv")
        ]
        for fname in files:
            fpath = Path(current_root) / fname
            kind = classify_non_sensitive_filename(fname)
            if kind == "web_code":
                result.web_files.append(fpath)
            elif kind == "config_json":
                # Keep non-sensitive JSON configs only as supporting files, count separately if standalone
                result.add_non_web("other", 1)
            elif kind == "text":
                if _is_plain_text_non_web(fpath):
                    result.add_non_web("plain_text", 1)
                    fpath.unlink(missing_ok=True)
                else:
                    result.web_files.append(fpath)
            else:
                result.add_non_web(kind, 1)
                fpath.unlink(missing_ok=True)

    if not result.web_files:
        shutil.rmtree(workspace, ignore_errors=True)
        breakdown = ", ".join(
            f"{count} {cat.replace('_', ' ')}" for cat, count in result.skipped_non_web.items() if count > 0
        )
        msg = (
            "Scan rejected: No valid web or source code files were found in this folder or repository."
        )
        if breakdown:
            msg += f" Detected only non-web files ({breakdown})."
        msg += " Please provide web-related files such as HTML, CSS, JavaScript, TypeScript, Python, or PHP."
        if result.sensitive_detected:
            listed = ", ".join(result.sensitive_detected[:10])
            suffix = f" (+{len(result.sensitive_detected) - 10} more)" if len(result.sensitive_detected) > 10 else ""
            msg += (
                f" Sensitive file(s)/folder(s) detected and skipped without inspecting or saving data: {listed}{suffix}."
            )
        raise ValueError(msg)

    return result
