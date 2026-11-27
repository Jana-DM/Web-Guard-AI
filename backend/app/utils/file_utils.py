import hashlib
import os
import shutil
import zipfile
from pathlib import Path
from typing import Iterable

MAX_ARCHIVE_FILES = 25000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 250 * 1024 * 1024  # 250 MB

WEB_CODE_EXTENSIONS = {
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
    ".java", ".go", ".rb",
    ".sql",
    ".graphql", ".gql",
    ".json", ".yaml", ".yml", ".toml", ".xml",
}

WEB_MANIFEST_FILENAMES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".gitignore",
    ".env",
}

IGNORED_TECH_DIRS = {
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
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
}


def safe_join(base_dir: Path, untrusted_path: str) -> Path:
    """Resolve an untrusted relative path inside base_dir, rejecting traversal."""
    cleaned = untrusted_path.replace("\\", "/").lstrip("/")
    target = (base_dir / cleaned).resolve()
    base_resolved = base_dir.resolve()
    if target != base_resolved and base_resolved not in target.parents:
        raise ValueError(f"Unsafe path traversal detected: {untrusted_path}")
    return target


def safe_extract_zip(zip_path: Path, dest_dir: Path) -> list[Path]:
    """Extract a ZIP archive safely with zip-slip and uncompressed size safety checks."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    total_size = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ARCHIVE_FILES:
            raise ValueError(f"Archive exceeds maximum allowed file count ({MAX_ARCHIVE_FILES}).")

        for info in infos:
            if info.is_dir():
                continue
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                raise ValueError(f"Symbolic links in archives are prohibited: {info.filename}")

            total_size += info.file_size
            if total_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise ValueError("Archive uncompressed size exceeds 250 MB safety threshold.")

            target = safe_join(dest_dir, info.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted.append(target)

    return extracted


def sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def collect_source_files(root: Path, extensions: Iterable[str] | None = None) -> list[Path]:
    ext_set = {e.lower() for e in extensions} if extensions is not None else WEB_CODE_EXTENSIONS
    results: list[Path] = []
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [
            d for d in dirs
            if d not in IGNORED_TECH_DIRS and not d.startswith(".venv") and not d.startswith("venv")
        ]
        for fname in files:
            fpath = Path(current_root) / fname
            low = fname.lower()
            if fpath.suffix.lower() in ext_set or low in WEB_MANIFEST_FILENAMES or low == ".env" or low.startswith(".env."):
                results.append(fpath)
    return results
