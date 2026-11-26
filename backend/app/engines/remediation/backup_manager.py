from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from app.config import get_settings


def create_backup(target_file: Path, remediation_id: str) -> Path:
    settings = get_settings()
    backup_root = Path(settings.BACKUP_DIR).resolve() / remediation_id
    backup_root.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_file = backup_root / f"{target_file.name}.{ts}.bak"
    shutil.copy2(target_file, backup_file)
    return backup_file


def restore_backup(backup_file: Path, destination_file: Path) -> None:
    if not backup_file.exists():
        raise FileNotFoundError(f"Backup file not found: {backup_file}")
    shutil.copy2(backup_file, destination_file)
