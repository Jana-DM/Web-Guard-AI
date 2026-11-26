from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class TargetCreateRequest(BaseModel):
    domain_or_url: str = Field(min_length=3, max_length=512)
    project_id: Optional[str] = None
    scope_notes: Optional[str] = None
    allowed_paths: List[str] = Field(default_factory=lambda: ["/"])


class TargetVerifyRequest(BaseModel):
    method: str = Field(pattern="^(dns_txt|http_well_known|explicit_authorization)$")
    signed_statement: Optional[str] = None


class TargetVerificationResponse(BaseModel):
    id: str
    method: str
    challenge_token: str
    verified: bool
    verification_details: dict
    verified_at: Optional[datetime]

    model_config = {"from_attributes": True}


class AuthorizedTargetResponse(BaseModel):
    id: str
    project_id: Optional[str]
    domain: str
    normalized_url: str
    target_type: str
    scope_notes: Optional[str]
    allowed_paths: List[str]
    is_authorized: bool
    authorization_method: Optional[str]
    authorized_at: Optional[datetime]
    created_at: datetime
    verifications: List[TargetVerificationResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class DomainScanCreateRequest(BaseModel):
    target_id: str
    enable_safe_owasp_checks: bool = True
    max_endpoints: int = Field(default=25, ge=1, le=60)
