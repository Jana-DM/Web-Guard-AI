from __future__ import annotations

import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.engines.code_scanner.content_validator import (
    classify_non_sensitive_filename,
    is_sensitive_path,
    sanitize_workspace_sensitive_items,
    validate_workspace_content,
)
from app.utils.file_utils import collect_source_files, safe_extract_zip, safe_join
from app.utils.validators import validate_github_url


def _workspace_bytes(workspace: Path) -> int:
    return sum(p.stat().st_size for p in workspace.rglob("*") if p.is_file())


def create_empty_upload_workspace() -> Path:
    """Create an isolated empty workspace directory for uploaded code scans."""
    settings = get_settings()
    workspace = Path(settings.UPLOAD_DIR).resolve() / f"scan_{uuid.uuid4().hex}"
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def append_files_to_workspace(
    workspace: Path,
    files: list[tuple[str, bytes]],
    cleanup_on_error: bool = False,
) -> dict[str, Any]:
    """
    Write uploaded non-sensitive source files or ZIP archives safely into workspace.
    Sensitive paths and media binaries are skipped before writing/reading disk.
    """
    settings = get_settings()
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    total_written = _workspace_bytes(workspace)
    skipped_sensitive: list[str] = []
    skipped_non_web: dict[str, int] = {}

    for filename, content in files:
        rel_name = Path(filename).name if "/" not in filename and "\\" not in filename else filename

        # Never inspect, write, or store sensitive files/folders
        is_sens, sens_label = is_sensitive_path(rel_name)
        if is_sens:
            if sens_label and sens_label not in skipped_sensitive:
                skipped_sensitive.append(sens_label)
            continue

        # Ensure safe path inside workspace
        safe_target = safe_join(workspace, rel_name)

        if safe_target.suffix.lower() == ".zip":
            total_written += len(content)
            if total_written > max_bytes:
                if cleanup_on_error:
                    shutil.rmtree(workspace, ignore_errors=True)
                raise ValueError(f"Upload exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB} MB.")
            safe_target.parent.mkdir(parents=True, exist_ok=True)
            safe_target.write_bytes(content)
            extract_dir = workspace / f"extracted_{safe_target.stem}"
            safe_extract_zip(
                safe_target,
                extract_dir,
                skipped_sensitive=skipped_sensitive,
                skipped_non_web=skipped_non_web,
            )
            safe_target.unlink(missing_ok=True)
            continue

        # Skip pure media binaries immediately without saving to disk
        kind = classify_non_sensitive_filename(rel_name)
        if kind in {"images", "videos", "audio", "documents"}:
            skipped_non_web[kind] = skipped_non_web.get(kind, 0) + 1
            continue

        total_written += len(content)
        if total_written > max_bytes:
            if cleanup_on_error:
                shutil.rmtree(workspace, ignore_errors=True)
            raise ValueError(f"Upload exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB} MB.")

        safe_target.parent.mkdir(parents=True, exist_ok=True)
        safe_target.write_bytes(content)

    return {"skipped_sensitive": skipped_sensitive, "skipped_non_web": skipped_non_web}


def prepare_upload_workspace(
    files: list[tuple[str, bytes]],
    pre_sensitive: list[str] | None = None,
    pre_non_web: dict[str, int] | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Persist uploaded files safely and verify the workspace contains valid web/code content."""
    workspace = create_empty_upload_workspace()
    ingest_meta = append_files_to_workspace(workspace, files, cleanup_on_error=True)
    merged_sensitive = list(dict.fromkeys([*(pre_sensitive or []), *ingest_meta["skipped_sensitive"]]))
    merged_non_web = dict(pre_non_web or {})
    for k, v in ingest_meta["skipped_non_web"].items():
        merged_non_web[k] = merged_non_web.get(k, 0) + v

    inspection = validate_workspace_content(
        workspace,
        pre_sensitive=merged_sensitive,
        pre_non_web=merged_non_web,
    )
    return workspace, {
        "sensitive_detected": inspection.sensitive_detected,
        "skipped_non_web": inspection.skipped_non_web,
        "scannable_count": len(inspection.web_files),
    }


def clone_github_repository(repository_url: str, branch: str | None = None) -> tuple[Path, dict[str, Any]]:
    """
    Shallow-clone a public GitHub repo with hooks disabled, strip any sensitive
    files/folders immediately without inspecting them, and verify valid web content exists.
    """
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

    sensitive_removed = sanitize_workspace_sensitive_items(workspace)
    inspection = validate_workspace_content(workspace, pre_sensitive=sensitive_removed)
    return workspace, {
        "sensitive_detected": inspection.sensitive_detected,
        "skipped_non_web": inspection.skipped_non_web,
        "scannable_count": len(inspection.web_files),
    }


def list_scannable_files(workspace: Path) -> list[Path]:
    return collect_source_files(workspace)
