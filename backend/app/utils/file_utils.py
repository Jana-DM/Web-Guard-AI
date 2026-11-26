import hashlib
import os
import shutil
import zipfile
from pathlib import Path
from typing import Iterable


MAX_ARCHIVE_FILES = 1500
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB


def safe_join(base_dir: Path, untrusted_path: str) -> Path:
    """Resolve an untrusted relative path inside base_dir, rejecting traversal."""
    cleaned = untrusted_path.replace("\\", "/").lstrip("/")
    target = (base_dir / cleaned).resolve()
    base_resolved = base_dir.resolve()
    if target != base_resolved and base_resolved not in target.parents:
        raise ValueError(f"Unsafe path traversal detected: {untrusted_path}")
    return target


def safe_extract_zip(zip_path: Path, dest_dir: Path) -> list[Path]:
    """Extract a ZIP archive safely with zip-slip, file count, and zip-bomb checks."""
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
            # Reject symlinks inside zip (external_attr unix symlink flag 0o120000)
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                raise ValueError(f"Symbolic links in archives are prohibited: {info.filename}")

            total_size += info.file_size
            if total_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise ValueError("Archive uncompressed size exceeds 50 MB safety threshold.")

            target = safe_join(dest_dir, info.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted.append(target)

    return extracted


def sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def collect_source_files(root: Path, extensions: Iterable[str] = (".py", ".js", ".jsx", ".ts", ".tsx")) -> list[Path]:
    ext_set = {e.lower() for e in extensions}
    ignored_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    results: list[Path] = []
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        for fname in files:
            fpath = Path(current_root) / fname
            if fpath.suffix.lower() in ext_set or fname in {
                "requirements.txt",
                "package.json",
                "package-lock.json",
                "pyproject.toml",
            }:
                results.append(fpath)
    return results
