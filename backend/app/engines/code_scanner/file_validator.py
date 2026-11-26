from __future__ import annotations

import shutil
import subprocess
import uuid
from pathlib import Path

from app.config import get_settings
from app.utils.file_utils import collect_source_files, safe_extract_zip, safe_join
from app.utils.validators import validate_github_url


def prepare_upload_workspace(files: list[tuple[str, bytes]]) -> Path:
    """Persist uploaded files or ZIP archives safely into an isolated workspace without executing anything."""
    settings = get_settings()
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    workspace = Path(settings.UPLOAD_DIR).resolve() / f"scan_{uuid.uuid4().hex}"
    workspace.mkdir(parents=True, exist_ok=True)

    total_written = 0
    for filename, content in files:
        total_written += len(content)
        if total_written > max_bytes:
            shutil.rmtree(workspace, ignore_errors=True)
            raise ValueError(f"Upload exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB} MB.")

        safe_target = safe_join(workspace, Path(filename).name if "/" not in filename and "\\" not in filename else filename)
        safe_target.parent.mkdir(parents=True, exist_ok=True)
        safe_target.write_bytes(content)

        if safe_target.suffix.lower() == ".zip":
            extract_dir = workspace / f"extracted_{safe_target.stem}"
            safe_extract_zip(safe_target, extract_dir)
            safe_target.unlink(missing_ok=True)

    return workspace


def clone_github_repository(repository_url: str, branch: str | None = None) -> Path:
    """Shallow-clone a public GitHub repo with hooks disabled for static-only inspection."""
    clean_url = validate_github_url(repository_url)
    settings = get_settings()
    workspace = Path(settings.UPLOAD_DIR).resolve() / f"gh_{uuid.uuid4().hex}"
    workspace.mkdir(parents=True, exist_ok=True)

    cmd = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.file.allow=never",
        "clone",
        "--depth",
        "1",
    ]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([clean_url, str(workspace)])

    env = {"GIT_TERMINAL_PROMPT": "0", "PATH": shutil.which("git") and str(Path(shutil.which("git")).parent) or ""}
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
    if proc.returncode != 0:
        shutil.rmtree(workspace, ignore_errors=True)
        raise ValueError(f"GitHub repository clone failed: {proc.stderr.strip()[:300]}")

    return workspace


def list_scannable_files(workspace: Path) -> list[Path]:
    return collect_source_files(workspace)
