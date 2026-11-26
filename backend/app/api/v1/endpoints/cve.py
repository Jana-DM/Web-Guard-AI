from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.ai.vulnerability_explainer import explain_cve
from app.core.exceptions import ResourceNotFoundError
from app.database.session import get_db
from app.dependencies import get_current_user
from app.engines.correlation.technology_cve_matcher import correlate_technologies_with_cves
from app.models.cve import CVEIntelligence
from app.models.scan_result import TechnologyFingerprint
from app.models.user import User
from app.schemas.intelligence import CorrelationRequest, CVERecordResponse

router = APIRouter(prefix="/cve", tags=["CVE Database"])


@router.get("")
def search_cves(
    q: Optional[str] = None,
    severity: Optional[str] = None,
    kev_only: bool = False,
    source: Optional[str] = None,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(CVEIntelligence)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.filter(
            or_(
                CVEIntelligence.cve_id.ilike(pattern),
                CVEIntelligence.title.ilike(pattern),
                CVEIntelligence.description.ilike(pattern),
            )
        )
    if severity:
        query = query.filter(CVEIntelligence.severity == severity.lower())
    if kev_only:
        query = query.filter(CVEIntelligence.is_kev.is_(True))

    total = query.count()
    rows = query.order_by(CVEIntelligence.is_kev.desc(), CVEIntelligence.created_at.desc()).offset(offset).limit(limit).all()
    if source:
        rows = [r for r in rows if source in (r.sources or [])]

    return {
        "total": total,
        "items": [CVERecordResponse.model_validate(r) for r in rows],
    }


@router.get("/{cve_id}")
def get_cve_detail(cve_id: str, _current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    cve = db.query(CVEIntelligence).filter(CVEIntelligence.cve_id == cve_id.upper()).first()
    if not cve:
        raise ResourceNotFoundError("CVE record")
    return {
        "record": CVERecordResponse.model_validate(cve),
        "ai_explanation": explain_cve(cve),
    }


@router.post("/correlate")
def correlate_cves(
    payload: CorrelationRequest,
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    tech_list = [{"product_name": t.product_name, "version": t.version} for t in payload.technologies]
    if payload.scan_job_id:
        fps = db.query(TechnologyFingerprint).filter(TechnologyFingerprint.scan_job_id == payload.scan_job_id).all()
        tech_list.extend({"product_name": fp.product_name, "version": fp.version} for fp in fps)

    results = correlate_technologies_with_cves(db, tech_list)
    return {"count": len(results), "correlations": results}
