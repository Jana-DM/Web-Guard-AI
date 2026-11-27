from fastapi import APIRouter

from app.api.v1.endpoints import (
    attack_surface,
    auth,
    code_scans,
    cve,
    dashboard,
    domain_scans,
    intelligence,
    remediation,
    reports,
    scan_stream,
    settings,
    users,
    validation,
    verification,
    vulnerabilities,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(dashboard.router)
api_router.include_router(intelligence.router)
api_router.include_router(cve.router)
api_router.include_router(domain_scans.router)
api_router.include_router(scan_stream.router)   # SSE — must be before code_scans to avoid route clash
api_router.include_router(code_scans.router)
api_router.include_router(attack_surface.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(validation.router)
api_router.include_router(remediation.router)
api_router.include_router(verification.router)
api_router.include_router(reports.router)
api_router.include_router(settings.router)
