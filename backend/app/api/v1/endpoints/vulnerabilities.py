from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.ai.vulnerability_explainer import explain_vulnerability
from app.database.session import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.schemas.vulnerability import VulnerabilityResponse
from app.services.vulnerability_service import get_vulnerability_or_404, list_vulnerabilities

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get("")
def get_vulnerabilities(
    severity: Optional[str] = None,
    classification: Optional[str] = None,
    scan_job_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    items, total = list_vulnerabilities(
        db=db,
        severity=severity,
        classification=classification,
        scan_job_id=scan_job_id,
        status=status,
        limit=limit,
        offset=offset,
    )
    return {
        "total": total,
        "items": [VulnerabilityResponse.model_validate(i) for i in items],
    }


@router.get("/{vuln_id}")
def get_vulnerability_detail(
    vuln_id: str,
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    vuln = get_vulnerability_or_404(db, vuln_id)
    return {
        "vulnerability": VulnerabilityResponse.model_validate(vuln),
        "ai_explanation": explain_vulnerability(vuln),
    }
