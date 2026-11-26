import uuid
from typing import Optional
from sqlalchemy import Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, JSONType, TimestampMixin


class ScanResult(Base, TimestampMixin):
    __tablename__ = "scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    module_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="completed", nullable=False)
    data: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    scan_job = relationship("ScanJob", back_populates="results")


class TechnologyFingerprint(Base, TimestampMixin):
    __tablename__ = "technology_fingerprints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("authorized_targets.id", ondelete="SET NULL"), nullable=True, index=True)
    product_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    category: Mapped[str] = mapped_column(String(64), default="framework", nullable=False)
    detection_source: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    raw_evidence: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)

    scan_job = relationship("ScanJob", back_populates="fingerprints")
