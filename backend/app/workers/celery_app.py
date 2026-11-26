from celery import Celery
from celery.schedules import crontab

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "web_guard_ai",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.workers.scan_tasks",
        "app.workers.intelligence_tasks",
        "app.workers.report_tasks",
    ],
)

celery_app.conf.update(
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
    task_eager_propagates=True,
    timezone="UTC",
    enable_utc=True,
    beat_schedule={
        "daily-cybersecurity-intelligence-sync": {
            "task": "app.workers.intelligence_tasks.daily_intelligence_sync_task",
            "schedule": crontab(hour=settings.INTELLIGENCE_SYNC_HOUR_UTC, minute=0),
        }
    },
)
