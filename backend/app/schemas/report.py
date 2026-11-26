from typing import Optional
from pydantic import BaseModel, Field


class ReportGenerateRequest(BaseModel):
    scan_job_id: Optional[str] = None
    project_id: Optional[str] = None
    format: str = Field(default="markdown", pattern="^(json|markdown|html)$")
    include_non_confirmed: bool = True


class SettingsUpdateRequest(BaseModel):
    scan_http_timeout_seconds: Optional[float] = Field(default=None, ge=2.0, le=30.0)
    scan_max_redirects: Optional[int] = Field(default=None, ge=0, le=10)
    scan_max_endpoints: Optional[int] = Field(default=None, ge=1, le=100)
    intelligence_sync_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
