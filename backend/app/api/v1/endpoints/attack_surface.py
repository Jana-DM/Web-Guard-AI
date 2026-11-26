from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.exceptions import ResourceNotFoundError
from app.database.session import get_db
from app.dependencies import get_current_user
from app.engines.correlation.exposure_analyzer import build_exposure_summary
from app.engines.correlation.technology_cve_matcher import correlate_technologies_with_cves
from app.models.authorized_target import AuthorizedTarget
from app.models.scan_job import ScanJob
from app.models.scan_result import ScanResult, TechnologyFingerprint
from app.models.user import User

router = APIRouter(prefix="/attack-surface", tags=["Attack Surface"])


@router.get("")
def list_attack_surface_overview(_current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    targets = db.query(AuthorizedTarget).order_by(AuthorizedTarget.created_at.desc()).all()
    fps = db.query(TechnologyFingerprint).order_by(TechnologyFingerprint.created_at.desc()).limit(100).all()
    return {
        "targets": [
            {
                "id": t.id,
                "domain": t.domain,
                "normalized_url": t.normalized_url,
                "is_authorized": t.is_authorized,
                "authorization_method": t.authorization_method,
            }
            for t in targets
        ],
        "technologies": [
            {
                "id": f.id,
                "product_name": f.product_name,
                "version": f.version,
                "category": f.category,
                "detection_source": f.detection_source,
                "confidence": f.confidence,
            }
            for f in fps
        ],
    }


@router.get("/{target_id}")
def get_target_attack_surface(target_id: str, _current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == target_id).first()
    if not target:
        raise ResourceNotFoundError("AuthorizedTarget")

    latest_scan = (
        db.query(ScanJob)
        .filter(ScanJob.target_id == target_id)
        .order_by(ScanJob.created_at.desc())
        .first()
    )
    fps = (
        db.query(TechnologyFingerprint).filter(TechnologyFingerprint.scan_job_id == latest_scan.id).all()
        if latest_scan
        else []
    )
    endpoints: list[dict] = []
    dns_data: dict = {}
    tls_data: dict = {}

    if latest_scan:
        for res in db.query(ScanResult).filter(ScanResult.scan_job_id == latest_scan.id).all():
            if res.module_name == "endpoints":
                endpoints = res.data.get("payload", [])
            elif res.module_name == "dns":
                dns_data = res.data.get("payload", {})
            elif res.module_name == "tls":
                tls_data = res.data.get("payload", {})

    fp_dicts = [{"product_name": f.product_name, "version": f.version, "category": f.category} for f in fps]
    correlations = correlate_technologies_with_cves(db, fp_dicts)
    exposure = build_exposure_summary(fp_dicts, correlations, endpoints)

    return {
        "target": {"id": target.id, "domain": target.domain, "normalized_url": target.normalized_url, "is_authorized": target.is_authorized},
        "latest_scan_id": latest_scan.id if latest_scan else None,
        "technologies": fp_dicts,
        "endpoints": endpoints,
        "dns": dns_data,
        "tls": tls_data,
        "cve_correlations": correlations,
        "exposure_summary": exposure,
    }
