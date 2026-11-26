from app.database.session import SessionLocal
from app.services.intelligence_service import trigger_sync
from app.workers.celery_app import celery_app


@celery_app.task(name="app.workers.intelligence_tasks.daily_intelligence_sync_task")
def daily_intelligence_sync_task(sources: list[str] | None = None, days_back: int = 7) -> dict:
    db = SessionLocal()
    try:
        logs = trigger_sync(db=db, sources=sources, days_back=days_back)
        return {
            "sources_synced": len(logs),
            "created": sum(l.records_created for l in logs),
            "updated": sum(l.records_updated for l in logs),
        }
    finally:
        db.close()
