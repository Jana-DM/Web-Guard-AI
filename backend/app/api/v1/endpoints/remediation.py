from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.ai.remediation_assistant import explain_remediation
from app.core.exceptions import ResourceNotFoundError
from app.database.session import get_db
from app.dependencies import get_current_user, require_analyst
from app.models.audit_log import AuditLog
from app.models.remediation import RemediationRecord
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import RemediationApproveRequest, RemediationResponse
from app.services.remediation_service import create_remediation_proposal, process_remediation_approval

router = APIRouter(prefix="/remediation", tags=["Remediation"])


@router.get("", response_model=list[RemediationResponse])
def list_remediations(_current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(RemediationRecord).order_by(RemediationRecord.created_at.desc()).limit(100).all()


@router.post("/generate/{vulnerability_id}", status_code=status.HTTP_201_CREATED)
def generate_remediation(
    vulnerability_id: str,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    record = create_remediation_proposal(db, vulnerability_id=vulnerability_id, user_id=current_user.id)
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    guidance = explain_remediation(vuln, record) if vuln else record.rationale
    return {
        "remediation": RemediationResponse.model_validate(record),
        "ai_guidance": guidance,
    }


@router.post("/{remediation_id}/approve", response_model=RemediationResponse)
def approve_remediation(
    remediation_id: str,
    payload: RemediationApproveRequest,
    request: Request,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    record = process_remediation_approval(
        db=db,
        remediation_id=remediation_id,
        approver_id=current_user.id,
        approved=payload.approved,
        comment=payload.review_comment,
    )
    db.add(
        AuditLog(
            user_id=current_user.id,
            action="remediation_decision",
            resource_type="remediation_record",
            resource_id=record.id,
            ip_address=request.client.host if request.client else None,
            details={"approved": payload.approved, "status": record.status},
        )
    )
    db.commit()
    return record


@router.get("/{remediation_id}", response_model=RemediationResponse)
def get_remediation(remediation_id: str, _current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rec = db.query(RemediationRecord).filter(RemediationRecord.id == remediation_id).first()
    if not rec:
        raise ResourceNotFoundError("RemediationRecord")
    return rec
