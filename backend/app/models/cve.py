import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import Boolean, DateTime, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, JSONType, TimestampMixin


class CVEIntelligence(Base, TimestampMixin):
    __tablename__ = "cve_intelligence"
    __table_args__ = (
        Index("ix_cve_sev_kev", "severity", "is_kev"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False, index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    cwe_ids: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)

    affected_products: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    kev_date_added: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    patch_urls: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    references: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    sources: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    dedup_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    update_history: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)

    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_modified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
