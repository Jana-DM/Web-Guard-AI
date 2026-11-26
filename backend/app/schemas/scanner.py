from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class GitHubScanRequest(BaseModel):
    repository_url: str = Field(min_length=15, max_length=512)
    project_id: Optional[str] = None
    branch: Optional[str] = None


class ScanJobResponse(BaseModel):
    id: str
    project_id: Optional[str]
    target_id: Optional[str]
    scan_type: str
    target_label: str
    status: str
    progress: int
    summary: dict[str, Any]
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class TechnologyFingerprintResponse(BaseModel):
    id: str
    product_name: str
    version: Optional[str]
    category: str
    detection_source: str
    confidence: float
    raw_evidence: dict[str, Any]

    model_config = {"from_attributes": True}


class ScanDetailResponse(BaseModel):
    job: ScanJobResponse
    results: List[dict[str, Any]]
    fingerprints: List[TechnologyFingerprintResponse]
    vulnerabilities_count: int
