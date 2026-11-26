from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.engines.intelligence.sync_manager import sync_intelligence_sources
from app.models.advisory import SecurityAdvisory, SyncLog
from app.models.cve import CVEIntelligence


def get_intelligence_overview(db: Session) -> dict:
    total_cves = db.query(func.count(CVEIntelligence.id)).scalar() or 0
    kev_count = db.query(func.count(CVEIntelligence.id)).filter(CVEIntelligence.is_kev.is_(True)).scalar() or 0
    advisories_count = db.query(func.count(SecurityAdvisory.id)).scalar() or 0
    last_sync = (
        db.query(SyncLog)
        .filter(SyncLog.status.in_(["completed", "partial"]))
        .order_by(SyncLog.completed_at.desc())
        .first()
    )
    recent_logs = db.query(SyncLog).order_by(SyncLog.started_at.desc()).limit(10).all()
    recent_advisories = db.query(SecurityAdvisory).order_by(SecurityAdvisory.created_at.desc()).limit(10).all()

    return {
        "total_cves": total_cves,
        "kev_count": kev_count,
        "advisories_count": advisories_count,
        "last_successful_sync": last_sync.completed_at.isoformat() if last_sync and last_sync.completed_at else None,
        "recent_sync_logs": recent_logs,
        "recent_advisories": recent_advisories,
    }


def trigger_sync(db: Session, sources: list[str] | None = None, days_back: int = 7) -> list[SyncLog]:
    return sync_intelligence_sources(db=db, sources=sources, days_back=days_back)
