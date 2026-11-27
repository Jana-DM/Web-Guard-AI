import json
import shutil
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.exceptions import ResourceNotFoundError
from app.database.session import get_db
from app.dependencies import get_current_user, require_analyst
from app.engines.code_scanner.content_validator import validate_workspace_content
from app.engines.code_scanner.file_validator import (
    append_files_to_workspace,
    clone_github_repository,
    create_empty_upload_workspace,
    prepare_upload_workspace,
)
from app.models.audit_log import AuditLog
from app.models.scan_job import ScanJob
from app.models.user import User
from app.schemas.scanner import GitHubScanRequest, ScanJobResponse
from app.services.scan_service import execute_code_scan_job

router = APIRouter(prefix="/code-scans", tags=["Code Scanner"])


class ChunkedUploadInitRequest(BaseModel):
    target_label: str = Field(default="uploaded_folder", max_length=255)
    total_files: int = Field(ge=1, le=50000)
    skipped_sensitive: list[str] = Field(default_factory=list)
    skipped_non_web: dict[str, int] = Field(default_factory=dict)


def _parse_json_meta(raw: str | None, fallback: Any) -> Any:
    if not raw:
        return fallback
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, type(fallback)) else fallback
    except ValueError:
        return fallback


def _format_upload_label(files: list[UploadFile]) -> str:
    if len(files) == 1:
        return files[0].filename or "uploaded_source"
    roots = {
        (f.filename or "").replace("\\", "/").split("/")[0]
        for f in files
        if "/" in (f.filename or "").replace("\\", "/")
    }
    if len(roots) == 1:
        return f"{next(iter(roots))} ({len(files)} files)"
    return f"{len(files)} uploaded items"


def _get_owned_upload_job(db: Session, scan_id: str, current_user: User) -> ScanJob:
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise ResourceNotFoundError("ScanJob")
    if job.initiated_by != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to modify this scan job.")
    if not job.source_path:
        raise HTTPException(status_code=400, detail="Scan job has no upload workspace.")
    return job


@router.post("/upload", response_model=ScanJobResponse, status_code=status.HTTP_201_CREATED)
async def upload_and_scan_code(
    request: Request,
    files: list[UploadFile] = File(...),
    skipped_sensitive_json: str | None = Form(default=None),
    skipped_non_web_json: str | None = Form(default=None),
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    if not files:
        raise HTTPException(status_code=400, detail="At least one source file or ZIP archive is required.")

    pre_sensitive = _parse_json_meta(skipped_sensitive_json, [])
    pre_non_web = _parse_json_meta(skipped_non_web_json, {})

    file_tuples: list[tuple[str, bytes]] = []
    for f in files:
        content = await f.read()
        file_tuples.append((f.filename or "uploaded_file.py", content))

    try:
        workspace, content_meta = prepare_upload_workspace(
            file_tuples,
            pre_sensitive=pre_sensitive,
            pre_non_web=pre_non_web,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    label = _format_upload_label(files)
    scan_job = ScanJob(
        initiated_by=current_user.id,
        scan_type="code_upload",
        target_label=label,
        source_path=str(workspace),
        status="queued",
        progress=0,
    )
    db.add(scan_job)
    db.add(
        AuditLog(
            user_id=current_user.id,
            action="code_upload_scan_started",
            resource_type="scan_job",
            resource_id=scan_job.id,
            ip_address=request.client.host if request.client else None,
            details={"files_count": content_meta.get("scannable_count", len(files)), "label": label},
        )
    )
    db.commit()
    db.refresh(scan_job)

    return execute_code_scan_job(db=db, scan_job=scan_job, workspace=workspace, extra_summary=content_meta)


@router.post("/upload/init", response_model=ScanJobResponse, status_code=status.HTTP_201_CREATED)
def init_chunked_code_upload(
    payload: ChunkedUploadInitRequest,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """Initialize a chunked folder upload session supporting large folders of any file count."""
    workspace = create_empty_upload_workspace()
    scan_job = ScanJob(
        initiated_by=current_user.id,
        scan_type="code_upload",
        target_label=payload.target_label,
        source_path=str(workspace),
        status="queued",
        progress=0,
        summary={
            "expected_files": payload.total_files,
            "uploaded_files": 0,
            "sensitive_detected": list(dict.fromkeys(payload.skipped_sensitive)),
            "skipped_non_web": dict(payload.skipped_non_web),
        },
    )
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)
    return scan_job


@router.post("/upload/{scan_id}/chunk")
async def upload_code_chunk(
    scan_id: str,
    files: list[UploadFile] = File(...),
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """Append a batch of non-sensitive files from a folder to an initialized upload workspace."""
    job = _get_owned_upload_job(db, scan_id, current_user)
    if not files:
        raise HTTPException(status_code=400, detail="Chunk contains no files.")

    file_tuples: list[tuple[str, bytes]] = []
    for f in files:
        content = await f.read()
        file_tuples.append((f.filename or "uploaded_file.py", content))

    try:
        ingest_meta = append_files_to_workspace(Path(job.source_path), file_tuples, cleanup_on_error=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    summary = dict(job.summary or {})
    uploaded = int(summary.get("uploaded_files", 0)) + len(file_tuples)
    expected = max(int(summary.get("expected_files", uploaded)), 1)
    summary["uploaded_files"] = uploaded
    summary["sensitive_detected"] = list(
        dict.fromkeys([*(summary.get("sensitive_detected") or []), *ingest_meta["skipped_sensitive"]])
    )
    non_web = dict(summary.get("skipped_non_web") or {})
    for k, v in ingest_meta["skipped_non_web"].items():
        non_web[k] = non_web.get(k, 0) + v
    summary["skipped_non_web"] = non_web
    job.summary = summary
    job.progress = min(14, int((uploaded / expected) * 14))
    db.commit()
    return {"scan_id": job.id, "chunk_files": len(file_tuples), "uploaded_files": uploaded}


@router.post("/upload/{scan_id}/execute", response_model=ScanJobResponse)
def execute_chunked_code_upload(
    scan_id: str,
    request: Request,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    """Validate web content and run static code analysis once all folder chunks have been uploaded."""
    job = _get_owned_upload_job(db, scan_id, current_user)
    summary = dict(job.summary or {})
    workspace = Path(job.source_path)

    try:
        inspection = validate_workspace_content(
            workspace,
            pre_sensitive=summary.get("sensitive_detected") or [],
            pre_non_web=summary.get("skipped_non_web") or {},
        )
    except ValueError as exc:
        shutil.rmtree(workspace, ignore_errors=True)
        db.delete(job)
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db.add(
        AuditLog(
            user_id=current_user.id,
            action="code_upload_scan_started",
            resource_type="scan_job",
            resource_id=job.id,
            ip_address=request.client.host if request.client else None,
            details={"files_count": len(inspection.web_files), "label": job.target_label, "chunked": True},
        )
    )
    db.commit()
    return execute_code_scan_job(
        db=db,
        scan_job=job,
        workspace=workspace,
        extra_summary={
            "sensitive_detected": inspection.sensitive_detected,
            "skipped_non_web": inspection.skipped_non_web,
        },
    )


@router.post("/github", response_model=ScanJobResponse, status_code=status.HTTP_201_CREATED)
def scan_github_repo(
    payload: GitHubScanRequest,
    request: Request,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    try:
        workspace, content_meta = clone_github_repository(payload.repository_url, branch=payload.branch)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan_job = ScanJob(
        project_id=payload.project_id,
        initiated_by=current_user.id,
        scan_type="code_github",
        target_label=payload.repository_url,
        source_path=str(workspace),
        status="queued",
        progress=0,
    )
    db.add(scan_job)
    db.add(
        AuditLog(
            user_id=current_user.id,
            action="github_scan_started",
            resource_type="scan_job",
            resource_id=scan_job.id,
            ip_address=request.client.host if request.client else None,
            details={"repository_url": payload.repository_url},
        )
    )
    db.commit()
    db.refresh(scan_job)

    return execute_code_scan_job(db=db, scan_job=scan_job, workspace=workspace, extra_summary=content_meta)


@router.get("/{scan_id}", response_model=ScanJobResponse)
def get_code_scan(scan_id: str, _current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise ResourceNotFoundError("ScanJob")
    return job
