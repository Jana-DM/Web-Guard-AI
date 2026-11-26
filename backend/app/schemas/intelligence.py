from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class CVERecordResponse(BaseModel):
    id: str
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    cwe_ids: List[str]
    affected_products: List[dict[str, Any]]
    is_kev: bool
    kev_date_added: Optional[str]
    patch_available: bool
    patch_urls: List[str]
    references: List[str]
    sources: List[str]
    update_history: List[dict[str, Any]]
    published_at: Optional[datetime]
    last_modified_at: Optional[datetime]

    model_config = {"from_attributes": True}


class SyncLogResponse(BaseModel):
    id: str
    source: str
    status: str
    records_fetched: int
    records_created: int
    records_updated: int
    duplicates_skipped: int
    details: dict[str, Any]
    error_message: Optional[str]
    started_at: datetime
    completed_at: Optional[datetime]

    model_config = {"from_attributes": True}


class IntelligenceSyncRequest(BaseModel):
    sources: List[str] = Field(default_factory=lambda: ["nvd", "cisa_kev", "github", "cve_program", "vendor", "owasp"])
    days_back: int = Field(default=7, ge=1, le=90)


class TechnologyInput(BaseModel):
    product_name: str
    version: Optional[str] = None


class CorrelationRequest(BaseModel):
    scan_job_id: Optional[str] = None
    technologies: List[TechnologyInput] = Field(default_factory=list)
