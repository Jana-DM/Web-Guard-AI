from __future__ import annotations

from sqlalchemy.orm import Session

from app.engines.validation.finding_classifier import validate_and_classify_findings
from app.models.vulnerability import Vulnerability


def revalidate_scan_findings(db: Session, scan_job_id: str) -> list[Vulnerability]:
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_job_id == scan_job_id).all()
    raw_inputs = [
        {
            "title": v.title,
            "description": v.description,
            "category": v.category,
            "source_engine": v.source_engine,
            "severity": v.severity,
            "cwe_id": v.cwe_id,
            "cve_id": v.cve_id,
            "location": v.location,
            "file_path": v.file_path,
            "line_number": v.line_number,
            "code_snippet": v.code_snippet,
            "evidence": v.evidence_records[0].raw_artifact if v.evidence_records else {},
        }
        for v in vulns
    ]
    revalidated = validate_and_classify_findings(raw_inputs)
    for v, res in zip(vulns, revalidated):
        v.classification = res["classification"]
        v.confidence_score = res["confidence_score"]
        v.validation_summary = res["validation_summary"]
        v.validation_stages = res["validation_stages"]
    db.commit()
    return vulns
