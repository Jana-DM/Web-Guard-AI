from pathlib import Path
from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.exceptions import ResourceNotFoundError
from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.schemas.report import ReportGenerateRequest
from app.services.report_service import generate_report_file
from app.utils.file_utils import safe_join

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("/generate")
def generate_report(
    payload: ReportGenerateRequest,
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return generate_report_file(
        db=db,
        report_format=payload.format,
        scan_job_id=payload.scan_job_id,
        include_non_confirmed=payload.include_non_confirmed,
    )


@router.get("")
def list_reports(_current_user: User = Depends(get_current_user)):
    reports_dir = Path(get_settings().REPORTS_DIR).resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(reports_dir.glob("webguard_report_*"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [
        {
            "filename": f.name,
            "size_bytes": f.stat().st_size,
            "download_url": f"/api/v1/reports/{f.name}/download",
        }
        for f in files[:50]
    ]


@router.get("/{filename}/download")
def download_report(filename: str, _current_user: User = Depends(get_current_user)):
    reports_dir = Path(get_settings().REPORTS_DIR).resolve()
    try:
        target = safe_join(reports_dir, filename)
    except ValueError as exc:
        raise ResourceNotFoundError("Report") from exc
    if not target.exists():
        raise ResourceNotFoundError("Report")
    return FileResponse(path=target, filename=target.name)
