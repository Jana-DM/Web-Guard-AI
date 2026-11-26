import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, JSONType, TimestampMixin


class RemediationRecord(Base, TimestampMixin):
    __tablename__ = "remediation_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vulnerability_id: Mapped[str] = mapped_column(String(36), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    file_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    original_code: Mapped[str] = mapped_column(Text, nullable=False)
    proposed_code: Mapped[str] = mapped_column(Text, nullable=False)
    diff_preview: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[str] = mapped_column(String(32), default="pending_approval", nullable=False, index=True)  # pending_approval, approved_applied, rejected, rolled_back
    backup_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    change_history: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    vulnerability = relationship("Vulnerability", back_populates="remediation_records")
    verifications = relationship("VerificationResult", back_populates="remediation", cascade="all, delete-orphan")


class VerificationResult(Base, TimestampMixin):
    __tablename__ = "verification_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    remediation_id: Mapped[str] = mapped_column(String(36), ForeignKey("remediation_records.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_job_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True)

    original_finding_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    new_issues_introduced: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False)  # verified_fixed, still_vulnerable, regression_detected
    details: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    remediation = relationship("RemediationRecord", back_populates="verifications")
