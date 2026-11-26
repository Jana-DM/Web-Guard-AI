from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.dependencies import get_current_user, require_analyst
from app.models.advisory import SyncLog
from app.models.user import User
from app.schemas.intelligence import IntelligenceSyncRequest, SyncLogResponse
from app.services.intelligence_service import get_intelligence_overview, trigger_sync

router = APIRouter(prefix="/intelligence", tags=["Threat Intelligence"])


@router.get("/overview")
def intelligence_overview(_current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    data = get_intelligence_overview(db)
    return {
        "total_cves": data["total_cves"],
        "kev_count": data["kev_count"],
        "advisories_count": data["advisories_count"],
        "last_successful_sync": data["last_successful_sync"],
        "recent_sync_logs": [SyncLogResponse.model_validate(l) for l in data["recent_sync_logs"]],
        "recent_advisories": [
            {
                "id": a.id,
                "advisory_id": a.advisory_id,
                "source": a.source,
                "title": a.title,
                "summary": a.summary,
                "severity": a.severity,
                "cve_ids": a.cve_ids,
                "advisory_url": a.advisory_url,
                "published_at": a.published_at.isoformat() if a.published_at else None,
            }
            for a in data["recent_advisories"]
        ],
    }


@router.post("/sync", response_model=list[SyncLogResponse])
def sync_intelligence(
    payload: IntelligenceSyncRequest,
    _current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    return trigger_sync(db=db, sources=payload.sources, days_back=payload.days_back)


@router.get("/sync-logs", response_model=list[SyncLogResponse])
def list_sync_logs(limit: int = 30, _current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(SyncLog).order_by(SyncLog.started_at.desc()).limit(min(limit, 100)).all()
