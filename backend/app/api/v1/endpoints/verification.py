from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.dependencies import get_current_user, require_analyst
from app.models.audit_log import AuditLog
from app.models.remediation import VerificationResult
from app.models.user import User
from app.services.remediation_service import run_post_remediation_verification

router = APIRouter(prefix="/verification", tags=["Verification"])


@router.post("/run/{remediation_id}")
def verify_remediation(
    remediation_id: str,
    request: Request,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    result = run_post_remediation_verification(db=db, remediation_id=remediation_id)
    db.add(
        AuditLog(
            user_id=current_user.id,
            action="remediation_verified",
            resource_type="verification_result",
            resource_id=result.id,
            ip_address=request.client.host if request.client else None,
            details={"status": result.verification_status, "resolved": result.original_finding_resolved},
        )
    )
    db.commit()
    return {
        "id": result.id,
        "remediation_id": result.remediation_id,
        "original_finding_resolved": result.original_finding_resolved,
        "new_issues_introduced": result.new_issues_introduced,
        "verification_status": result.verification_status,
        "details": result.details,
        "verified_at": result.verified_at.isoformat(),
    }


@router.get("")
def list_verifications(_current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(VerificationResult).order_by(VerificationResult.verified_at.desc()).limit(50).all()
    return [
        {
            "id": r.id,
            "remediation_id": r.remediation_id,
            "original_finding_resolved": r.original_finding_resolved,
            "new_issues_introduced": r.new_issues_introduced,
            "verification_status": r.verification_status,
            "details": r.details,
            "verified_at": r.verified_at.isoformat(),
        }
        for r in rows
    ]
