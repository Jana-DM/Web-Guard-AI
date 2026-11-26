from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app.config import get_settings
from app.engines.remediation.backup_manager import create_backup
from app.models.remediation import RemediationRecord


def apply_approved_patch(record: RemediationRecord, approver_id: str, comment: str | None = None) -> RemediationRecord:
    """Apply an explicitly approved remediation patch after creating a backup.

    Never modifies remote live websites; only modifies managed source workspace files.
    """
    if record.status == "approved_applied":
        return record

    now = datetime.now(timezone.utc)
    history = list(record.change_history or [])

    if record.file_path:
        target = Path(record.file_path).resolve()
        upload_root = Path(get_settings().UPLOAD_DIR).resolve()
        if upload_root not in target.parents:
            raise ValueError("Refusing to modify file outside managed scan workspace.")
        if not target.exists():
            raise FileNotFoundError(f"Managed source file not found: {target}")

        backup_path = create_backup(target, record.id)
        record.backup_path = str(backup_path)
        target.write_text(record.proposed_code, encoding="utf-8")

    record.approved_by = approver_id
    record.approved_at = now
    record.applied_at = now
    record.status = "approved_applied"
    history.append({
        "timestamp": now.isoformat(),
        "action": "approved_and_applied",
        "actor": approver_id,
        "comment": comment or "Approved via Remediation Center",
    })
    record.change_history = history
    return record
