from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.ai.security_assistant import answer_security_question
from app.database.session import get_db
from app.dependencies import get_current_user, require_analyst
from app.models.user import User
from app.schemas.vulnerability import AIAnalyzeRequest, VulnerabilityResponse
from app.services.validation_service import revalidate_scan_findings

router = APIRouter(prefix="/validation", tags=["AI Vulnerability Validation"])


@router.post("/run/{scan_job_id}", response_model=list[VulnerabilityResponse])
def run_validation_pipeline(
    scan_job_id: str,
    _current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    vulns = revalidate_scan_findings(db, scan_job_id)
    return [VulnerabilityResponse.model_validate(v) for v in vulns]


@router.post("/ai-analyze")
def ai_security_analyst(
    payload: AIAnalyzeRequest,
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return answer_security_question(
        db=db,
        question=payload.question,
        vulnerability_id=payload.vulnerability_id,
        scan_job_id=payload.scan_job_id,
        cve_id=payload.cve_id,
    )
