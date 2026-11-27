"""
Real-Time Scan Progress — Server-Sent Events (SSE)
---------------------------------------------------
GET /code-scans/{scan_id}/stream

Streams JSON progress events until the scan completes or fails.
Events are emitted by polling the DB every ~600ms.

Event format (each line):  data: {...json...}\n\n
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.scan_job import ScanJob
from app.models.user import User
from app.models.vulnerability import Vulnerability

router = APIRouter(prefix="/code-scans", tags=["Code Scanner Real-Time"])

# Maps backend progress % → human-readable stage label
_STAGE_LABELS: list[tuple[int, str, str]] = [
    (0,  "queued",    "Queued — waiting to start"),
    (10, "starting",  "Starting security pipeline…"),
    (20, "inventory", "Step 1: Discovering & indexing project files"),
    (30, "validating","Step 2: Validating web technologies & languages"),
    (45, "secrets",   "Step 3: Scanning for sensitive keys & credentials"),
    (60, "scanning",  "Step 4: Running custom rule engine on source files"),
    (70, "bandit",    "Step 4b: Running Bandit static analyzer"),
    (80, "semgrep",   "Step 4c: Running Semgrep security rules"),
    (85, "deps",      "Step 4d: Checking dependency CVE database"),
    (90, "classify",  "Step 5: Classifying & validating findings (evidence-based)"),
    (95, "reporting", "Step 6: Building security dashboard report"),
    (100,"completed", "Scan complete ✓"),
]

def _stage_for_progress(pct: int) -> tuple[str, str]:
    label_key = "queued"
    label_human = "Queued"
    for threshold, key, human in _STAGE_LABELS:
        if pct >= threshold:
            label_key = key
            label_human = human
    return label_key, label_human


@router.get("/{scan_id}/stream")
async def stream_scan_progress(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    SSE endpoint: streams scan progress as newline-delimited JSON events.
    Closes automatically when status becomes 'completed' or 'failed'.
    """
    async def event_generator():
        last_progress = -1
        ticks = 0
        max_ticks = 600  # 600 × 0.6 s ≈ 6 minutes hard cap

        while ticks < max_ticks:
            # Refresh the scan job from DB
            db.expire_all()
            job: ScanJob | None = db.query(ScanJob).filter(ScanJob.id == scan_id).first()

            if not job:
                payload = json.dumps({
                    "type": "error",
                    "message": "Scan job not found",
                })
                yield f"data: {payload}\n\n"
                return

            pct = int(job.progress or 0)
            status = job.status or "queued"
            stage_key, stage_human = _stage_for_progress(pct)

            # Count vulnerabilities found so far
            vuln_count = db.query(Vulnerability).filter(Vulnerability.scan_job_id == scan_id).count()

            event: dict = {
                "type": "progress",
                "scan_id": scan_id,
                "status": status,
                "progress": pct,
                "stage_key": stage_key,
                "stage_label": stage_human,
                "vulnerabilities_found": vuln_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # Always send on first tick or when progress changes
            if pct != last_progress or ticks == 0:
                last_progress = pct
                yield f"data: {json.dumps(event)}\n\n"

            if status in ("completed", "failed"):
                # Send final event with full summary
                final: dict = {
                    "type": "final",
                    "scan_id": scan_id,
                    "status": status,
                    "progress": pct,
                    "stage_key": "completed" if status == "completed" else "failed",
                    "stage_label": "Scan complete ✓" if status == "completed" else "Scan failed",
                    "vulnerabilities_found": vuln_count,
                    "summary": job.summary or {},
                    "error_message": job.error_message,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                yield f"data: {json.dumps(final)}\n\n"
                return

            await asyncio.sleep(0.6)
            ticks += 1

        # Timeout
        yield f"data: {json.dumps({'type': 'error', 'message': 'Stream timeout'})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
