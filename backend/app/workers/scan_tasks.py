from pathlib import Path

from app.database.session import SessionLocal
from app.models.authorized_target import AuthorizedTarget
from app.models.scan_job import ScanJob
from app.services.scan_service import execute_code_scan_job, execute_domain_scan_job
from app.workers.celery_app import celery_app


@celery_app.task(name="app.workers.scan_tasks.run_domain_scan_task")
def run_domain_scan_task(
    scan_job_id: str,
    target_id: str,
    enable_safe_owasp_checks: bool = True,
    max_endpoints: int = 25,
) -> str:
    db = SessionLocal()
    try:
        scan_job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == target_id).first()
        if scan_job and target:
            execute_domain_scan_job(
                db=db,
                scan_job=scan_job,
                target=target,
                enable_safe_owasp_checks=enable_safe_owasp_checks,
                max_endpoints=max_endpoints,
            )
            return scan_job.status
        return "missing"
    finally:
        db.close()


@celery_app.task(name="app.workers.scan_tasks.run_code_scan_task")
def run_code_scan_task(scan_job_id: str, workspace_path: str) -> str:
    db = SessionLocal()
    try:
        scan_job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if scan_job:
            execute_code_scan_job(db=db, scan_job=scan_job, workspace=Path(workspace_path))
            return scan_job.status
        return "missing"
    finally:
        db.close()
