import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, JSONType, TimestampMixin


class ScanJob(Base, TimestampMixin):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    target_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("authorized_targets.id", ondelete="SET NULL"), nullable=True, index=True)
    initiated_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    scan_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # domain, code_upload, code_github, verification
    target_label: Mapped[str] = mapped_column(String(512), nullable=False)
    source_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False, index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    summary: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    project = relationship("Project", back_populates="scan_jobs")
    target = relationship("AuthorizedTarget", back_populates="scan_jobs")
    results = relationship("ScanResult", back_populates="scan_job", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan_job", cascade="all, delete-orphan")
    fingerprints = relationship("TechnologyFingerprint", back_populates="scan_job", cascade="all, delete-orphan")
