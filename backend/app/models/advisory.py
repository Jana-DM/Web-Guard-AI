import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, JSONType, TimestampMixin


class SecurityAdvisory(Base, TimestampMixin):
    __tablename__ = "security_advisories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    advisory_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # github, vendor, owasp, cisa_kev
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False, index=True)
    cve_ids: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    affected_packages: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    advisory_url: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class SyncLog(Base, TimestampMixin):
    __tablename__ = "sync_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # running, completed, partial, failed
    records_fetched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_updated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duplicates_skipped: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    details: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
