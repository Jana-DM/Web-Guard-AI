from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.core.exceptions import ResourceNotFoundError
from app.database.session import get_db
from app.dependencies import get_current_user, require_analyst
from app.engines.code_scanner.file_validator import clone_github_repository, prepare_upload_workspace
from app.models.audit_log import AuditLog
from app.models.scan_job import ScanJob
from app.models.user import User
from app.schemas.scanner import GitHubScanRequest, ScanJobResponse
from app.services.scan_service import execute_code_scan_job

router = APIRouter(prefix="/code-scans", tags=["Code Scanner"])


@router.post("/upload", response_model=ScanJobResponse, status_code=status.HTTP_201_CREATED)
async def upload_and_scan_code(
    request: Request,
    files: list[UploadFile] = File(...),
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    if not files:
        raise HTTPException(status_code=400, detail="At least one source file or ZIP archive is required.")

    file_tuples: list[tuple[str, bytes]] = []
    for f in files:
        content = await f.read()
        file_tuples.append((f.filename or "uploaded_file.py", content))

    try:
        workspace = prepare_upload_workspace(file_tuples)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    label = files[0].filename if len(files) == 1 else f"{len(files)} uploaded items"
    scan_job = ScanJob(
        initiated_by=current_user.id,
        scan_type="code_upload",
        target_label=label or "uploaded_source",
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
            details={"files_count": len(files), "label": label},
        )
    )
    db.commit()
    db.refresh(scan_job)

    return execute_code_scan_job(db=db, scan_job=scan_job, workspace=workspace)


@router.post("/github", response_model=ScanJobResponse, status_code=status.HTTP_201_CREATED)
def scan_github_repo(
    payload: GitHubScanRequest,
    request: Request,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    try:
        workspace = clone_github_repository(payload.repository_url, branch=payload.branch)
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

    return execute_code_scan_job(db=db, scan_job=scan_job, workspace=workspace)


@router.get("/{scan_id}", response_model=ScanJobResponse)
def get_code_scan(scan_id: str, _current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise ResourceNotFoundError("ScanJob")
    return job
