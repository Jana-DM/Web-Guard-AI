from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session, joinedload

from app.core.exceptions import ResourceNotFoundError
from app.database.session import get_db
from app.dependencies import get_current_user, require_analyst
from app.engines.domain_scanner.authorization import (
    assert_target_authorized,
    generate_verification_token,
    verification_expiry,
    verify_dns_txt,
    verify_explicit_authorization,
    verify_http_well_known,
)
from app.engines.domain_scanner.target_validator import resolve_and_validate_host
from app.models.audit_log import AuditLog
from app.models.authorized_target import AuthorizedTarget, TargetVerification
from app.models.scan_job import ScanJob
from app.models.scan_result import ScanResult, TechnologyFingerprint
from app.models.user import User
from app.schemas.domain import (
    AuthorizedTargetResponse,
    DomainScanCreateRequest,
    TargetCreateRequest,
    TargetVerifyRequest,
)
from app.schemas.scanner import ScanDetailResponse, ScanJobResponse, TechnologyFingerprintResponse
from app.services.scan_service import execute_domain_scan_job
from app.utils.validators import normalize_domain_or_url

router = APIRouter(prefix="/domain-scans", tags=["Domain Scanner"])


@router.post("/targets", response_model=AuthorizedTargetResponse, status_code=status.HTTP_201_CREATED)
def register_target(
    payload: TargetCreateRequest,
    request: Request,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    try:
        domain, normalized_url = normalize_domain_or_url(payload.domain_or_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Enforce SSRF/private IP check even when registering targets
    resolve_and_validate_host(domain)

    target = AuthorizedTarget(
        project_id=payload.project_id,
        created_by=current_user.id,
        domain=domain,
        normalized_url=normalized_url,
        target_type="domain",
        scope_notes=payload.scope_notes,
        allowed_paths=payload.allowed_paths or ["/"],
        is_authorized=False,
    )
    db.add(target)
    db.flush()

    token = generate_verification_token()
    verification = TargetVerification(
        target_id=target.id,
        method="dns_txt",
        challenge_token=token,
        verified=False,
        verification_details={
            "dns_txt_instruction": f"Add TXT record on _webguard-verify.{domain} with value: {token}",
            "http_instruction": f"Serve {normalized_url}/.well-known/webguard-verify.txt containing: {token}",
        },
        expires_at=verification_expiry(),
    )
    db.add(verification)
    db.add(
        AuditLog(
            user_id=current_user.id,
            action="target_registered",
            resource_type="authorized_target",
            resource_id=target.id,
            ip_address=request.client.host if request.client else None,
            details={"domain": domain},
        )
    )
    db.commit()
    db.refresh(target)
    return (
        db.query(AuthorizedTarget)
        .options(joinedload(AuthorizedTarget.verifications))
        .filter(AuthorizedTarget.id == target.id)
        .first()
    )


@router.get("/targets", response_model=list[AuthorizedTargetResponse])
def list_targets(_current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        db.query(AuthorizedTarget)
        .options(joinedload(AuthorizedTarget.verifications))
        .order_by(AuthorizedTarget.created_at.desc())
        .all()
    )


@router.post("/targets/{target_id}/verify", response_model=AuthorizedTargetResponse)
def verify_target(
    target_id: str,
    payload: TargetVerifyRequest,
    request: Request,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    target = (
        db.query(AuthorizedTarget)
        .options(joinedload(AuthorizedTarget.verifications))
        .filter(AuthorizedTarget.id == target_id)
        .first()
    )
    if not target:
        raise ResourceNotFoundError("AuthorizedTarget")

    latest_challenge = target.verifications[-1] if target.verifications else None
    token = latest_challenge.challenge_token if latest_challenge else generate_verification_token()

    if payload.method == "dns_txt":
        ok, details = verify_dns_txt(target.domain, token)
    elif payload.method == "http_well_known":
        ok, details = verify_http_well_known(target.domain, target.normalized_url, token)
    else:
        ok, details = verify_explicit_authorization(target.domain, payload.signed_statement, token)

    now = datetime.now(timezone.utc)
    ver_rec = TargetVerification(
        target_id=target.id,
        method=payload.method,
        challenge_token=token,
        verified=ok,
        verification_details=details,
        verified_at=now if ok else None,
        expires_at=verification_expiry(),
    )
    db.add(ver_rec)

    if ok:
        target.is_authorized = True
        target.authorization_method = payload.method
        target.authorized_at = now

    db.add(
        AuditLog(
            user_id=current_user.id,
            action="target_verification_attempt",
            resource_type="authorized_target",
            resource_id=target.id,
            ip_address=request.client.host if request.client else None,
            details={"method": payload.method, "verified": ok},
        )
    )
    db.commit()

    if not ok:
        raise HTTPException(status_code=400, detail=f"Verification failed: {details.get('reason', 'Token mismatch')}")

    return (
        db.query(AuthorizedTarget)
        .options(joinedload(AuthorizedTarget.verifications))
        .filter(AuthorizedTarget.id == target.id)
        .first()
    )


@router.post("", response_model=ScanJobResponse, status_code=status.HTTP_201_CREATED)
def start_domain_scan(
    payload: DomainScanCreateRequest,
    request: Request,
    current_user: User = Depends(require_analyst),
    db: Session = Depends(get_db),
):
    target = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == payload.target_id).first()
    assert_target_authorized(target)

    scan_job = ScanJob(
        project_id=target.project_id,
        target_id=target.id,
        initiated_by=current_user.id,
        scan_type="domain",
        target_label=target.normalized_url,
        status="queued",
        progress=0,
    )
    db.add(scan_job)
    db.add(
        AuditLog(
            user_id=current_user.id,
            action="domain_scan_started",
            resource_type="scan_job",
            resource_id=scan_job.id,
            ip_address=request.client.host if request.client else None,
            details={"domain": target.domain},
        )
    )
    db.commit()
    db.refresh(scan_job)

    execute_domain_scan_job(
        db=db,
        scan_job=scan_job,
        target=target,
        enable_safe_owasp_checks=payload.enable_safe_owasp_checks,
        max_endpoints=payload.max_endpoints,
    )
    return scan_job


@router.get("", response_model=list[ScanJobResponse])
def list_all_scans(
    scan_type: str | None = None,
    limit: int = 50,
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(ScanJob)
    if scan_type:
        query = query.filter(ScanJob.scan_type == scan_type)
    return query.order_by(ScanJob.created_at.desc()).limit(min(limit, 100)).all()


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan_detail(scan_id: str, _current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise ResourceNotFoundError("ScanJob")
    results = db.query(ScanResult).filter(ScanResult.scan_job_id == job.id).all()
    fps = db.query(TechnologyFingerprint).filter(TechnologyFingerprint.scan_job_id == job.id).all()
    return ScanDetailResponse(
        job=ScanJobResponse.model_validate(job),
        results=[{"module": r.module_name, "status": r.status, "data": r.data} for r in results],
        fingerprints=[TechnologyFingerprintResponse.model_validate(f) for f in fps],
        vulnerabilities_count=len(job.vulnerabilities),
    )
