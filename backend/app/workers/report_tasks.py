from app.database.session import SessionLocal
from app.services.report_service import generate_report_file
from app.workers.celery_app import celery_app


@celery_app.task(name="app.workers.report_tasks.generate_report_task")
def generate_report_task(
    report_format: str = "markdown",
    scan_job_id: str | None = None,
    include_non_confirmed: bool = True,
) -> dict:
    db = SessionLocal()
    try:
        return generate_report_file(
            db=db,
            report_format=report_format,
            scan_job_id=scan_job_id,
            include_non_confirmed=include_non_confirmed,
        )
    finally:
        db.close()
