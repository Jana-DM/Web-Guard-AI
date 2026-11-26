from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.core.exceptions import ResourceNotFoundError, ValidationFailureError
from app.engines.remediation.fix_generator import generate_code_fix
from app.engines.remediation.patch_manager import apply_approved_patch
from app.engines.remediation.verification_engine import verify_remediated_code
from app.models.remediation import RemediationRecord, VerificationResult
from app.models.vulnerability import Vulnerability


def create_remediation_proposal(db: Session, vulnerability_id: str, user_id: str) -> RemediationRecord:
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    if not vuln:
        raise ResourceNotFoundError("Vulnerability")
    if vuln.target_id and not vuln.file_path:
        raise ValidationFailureError("External live websites cannot be automatically modified; provide remediation guidance manually.")

    fix = generate_code_fix(vuln)
    record = RemediationRecord(
        vulnerability_id=vuln.id,
        created_by=user_id,
        file_path=fix["file_path"],
        original_code=fix["original_code"],
        proposed_code=fix["proposed_code"],
        diff_preview=fix["diff_preview"],
        rationale=fix["rationale"],
        status="pending_approval",
        change_history=[
            {"timestamp": datetime.now(timezone.utc).isoformat(), "action": "proposal_generated", "actor": user_id}
        ],
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def process_remediation_approval(
    db: Session,
    remediation_id: str,
    approver_id: str,
    approved: bool,
    comment: str | None = None,
) -> RemediationRecord:
    record = db.query(RemediationRecord).filter(RemediationRecord.id == remediation_id).first()
    if not record:
        raise ResourceNotFoundError("RemediationRecord")

    if not approved:
        record.status = "rejected"
        record.approved_by = approver_id
        record.approved_at = datetime.now(timezone.utc)
        history = list(record.change_history or [])
        history.append({"timestamp": datetime.now(timezone.utc).isoformat(), "action": "rejected", "actor": approver_id, "comment": comment})
        record.change_history = history
        db.commit()
        db.refresh(record)
        return record

    apply_approved_patch(record, approver_id=approver_id, comment=comment)
    vuln = db.query(Vulnerability).filter(Vulnerability.id == record.vulnerability_id).first()
    if vuln:
        vuln.status = "remediated"
    db.commit()
    db.refresh(record)
    return record


def run_post_remediation_verification(db: Session, remediation_id: str) -> VerificationResult:
    record = db.query(RemediationRecord).filter(RemediationRecord.id == remediation_id).first()
    if not record:
        raise ResourceNotFoundError("RemediationRecord")
    if record.status != "approved_applied":
        raise ValidationFailureError("Remediation must be explicitly approved and applied before verification.")

    vuln = db.query(Vulnerability).filter(Vulnerability.id == record.vulnerability_id).first()
    if not vuln:
        raise ResourceNotFoundError("Vulnerability")

    outcome = verify_remediated_code(record, vuln)
    verification = VerificationResult(
        remediation_id=record.id,
        scan_job_id=vuln.scan_job_id,
        original_finding_resolved=outcome["original_finding_resolved"],
        new_issues_introduced=outcome["new_issues_introduced"],
        verification_status=outcome["verification_status"],
        details=outcome["details"],
        verified_at=outcome["verified_at"],
    )
    if outcome["verification_status"] == "verified_fixed":
        vuln.status = "verified"

    db.add(verification)
    db.commit()
    db.refresh(verification)
    return verification
