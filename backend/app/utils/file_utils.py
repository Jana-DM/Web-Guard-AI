import hashlib
import os
import shutil
import zipfile
from pathlib import Path
from typing import Iterable

from app.engines.code_scanner.content_validator import (
    IGNORED_TECH_DIRS,
    WEB_CODE_EXTENSIONS,
    WEB_MANIFEST_FILENAMES,
    classify_non_sensitive_filename,
    is_sensitive_path,
)

MAX_ARCHIVE_FILES = 25000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 250 * 1024 * 1024  # 250 MB


def safe_join(base_dir: Path, untrusted_path: str) -> Path:
    """Resolve an untrusted relative path inside base_dir, rejecting traversal."""
    cleaned = untrusted_path.replace("\\", "/").lstrip("/")
    target = (base_dir / cleaned).resolve()
    base_resolved = base_dir.resolve()
    if target != base_resolved and base_resolved not in target.parents:
        raise ValueError(f"Unsafe path traversal detected: {untrusted_path}")
    return target


def safe_extract_zip(
    zip_path: Path,
    dest_dir: Path,
    skipped_sensitive: list[str] | None = None,
    skipped_non_web: dict[str, int] | None = None,
) -> list[Path]:
    """Extract a ZIP archive safely while skipping sensitive and binary media entries without reading them."""
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

            # Never inspect, extract, or persist sensitive files/folders inside archives
            is_sens, sens_label = is_sensitive_path(info.filename)
            if is_sens:
                if skipped_sensitive is not None and sens_label and sens_label not in skipped_sensitive:
                    skipped_sensitive.append(sens_label)
                continue

            kind = classify_non_sensitive_filename(info.filename)
            if kind in {"images", "videos", "audio", "documents"}:
                if skipped_non_web is not None:
                    skipped_non_web[kind] = skipped_non_web.get(kind, 0) + 1
                continue

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
            if fpath.suffix.lower() in ext_set or fname.lower() in WEB_MANIFEST_FILENAMES:
                results.append(fpath)
    return results
