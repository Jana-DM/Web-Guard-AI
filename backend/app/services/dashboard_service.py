from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.advisory import SyncLog
from app.models.authorized_target import AuthorizedTarget
from app.models.cve import CVEIntelligence
from app.models.remediation import RemediationRecord
from app.models.scan_job import ScanJob
from app.models.vulnerability import Vulnerability


def get_dashboard_summary(db: Session) -> dict:
    total_scans = db.query(func.count(ScanJob.id)).scalar() or 0
    total_targets = db.query(func.count(AuthorizedTarget.id)).scalar() or 0
    verified_targets = db.query(func.count(AuthorizedTarget.id)).filter(AuthorizedTarget.is_authorized.is_(True)).scalar() or 0
    total_cves = db.query(func.count(CVEIntelligence.id)).scalar() or 0
    kev_cves = db.query(func.count(CVEIntelligence.id)).filter(CVEIntelligence.is_kev.is_(True)).scalar() or 0

    sev_rows = db.query(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity).all()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, cnt in sev_rows:
        severity_counts[sev] = cnt

    class_rows = (
        db.query(Vulnerability.classification, func.count(Vulnerability.id))
        .group_by(Vulnerability.classification)
        .all()
    )
    classification_counts = {"CONFIRMED": 0, "POTENTIAL": 0, "NEEDS REVIEW": 0, "NOT REPRODUCED": 0}
    for cls, cnt in class_rows:
        classification_counts[cls] = cnt

    remediated_count = (
        db.query(func.count(RemediationRecord.id))
        .filter(RemediationRecord.status == "approved_applied")
        .scalar()
        or 0
    )

    last_sync = (
        db.query(SyncLog)
        .filter(SyncLog.status.in_(["completed", "partial"]))
        .order_by(SyncLog.completed_at.desc())
        .first()
    )

    recent_scans = db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(6).all()

    return {
        "metrics": {
            "total_scans": total_scans,
            "total_targets": total_targets,
            "verified_targets": verified_targets,
            "total_cves": total_cves,
            "kev_cves": kev_cves,
            "total_vulnerabilities": sum(severity_counts.values()),
            "confirmed_vulnerabilities": classification_counts["CONFIRMED"],
            "remediated_count": remediated_count,
        },
        "severity_distribution": severity_counts,
        "classification_distribution": classification_counts,
        "last_intelligence_sync": last_sync.completed_at.isoformat() if last_sync and last_sync.completed_at else None,
        "recent_scans": [
            {
                "id": s.id,
                "scan_type": s.scan_type,
                "target_label": s.target_label,
                "status": s.status,
                "progress": s.progress,
                "created_at": s.created_at.isoformat(),
                "summary": s.summary,
            }
            for s in recent_scans
        ],
    }
