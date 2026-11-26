from fastapi import APIRouter, Depends

from app.config import get_settings
from app.dependencies import get_current_user, require_admin
from app.models.user import User
from app.schemas.report import SettingsUpdateRequest

router = APIRouter(prefix="/settings", tags=["Settings"])

_RUNTIME_OVERRIDES: dict[str, object] = {}


@router.get("")
def get_platform_settings(_current_user: User = Depends(get_current_user)):
    settings = get_settings()
    return {
        "app_name": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
        "scan_http_timeout_seconds": _RUNTIME_OVERRIDES.get("scan_http_timeout_seconds", settings.SCAN_HTTP_TIMEOUT_SECONDS),
        "scan_max_redirects": _RUNTIME_OVERRIDES.get("scan_max_redirects", settings.SCAN_MAX_REDIRECTS),
        "scan_max_endpoints": _RUNTIME_OVERRIDES.get("scan_max_endpoints", settings.SCAN_MAX_ENDPOINTS),
        "scan_rate_limit_per_minute": settings.SCAN_RATE_LIMIT_PER_MINUTE,
        "intelligence_sync_hour_utc": _RUNTIME_OVERRIDES.get("intelligence_sync_hour_utc", settings.INTELLIGENCE_SYNC_HOUR_UTC),
        "llm_provider": settings.LLM_PROVIDER,
        "allow_localhost_scanning": settings.ALLOW_LOCALHOST_SCANNING,
    }


@router.put("")
def update_platform_settings(
    payload: SettingsUpdateRequest,
    _admin: User = Depends(require_admin),
):
    for field, val in payload.model_dump(exclude_none=True).items():
        _RUNTIME_OVERRIDES[field] = val
    return {"updated": _RUNTIME_OVERRIDES}
