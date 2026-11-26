import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, JSONType, TimestampMixin


class AuthorizedTarget(Base, TimestampMixin):
    __tablename__ = "authorized_targets"
    __table_args__ = (
        Index("ix_authorized_targets_domain_status", "domain", "is_authorized"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    created_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    normalized_url: Mapped[str] = mapped_column(String(512), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), default="domain", nullable=False)
    scope_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    allowed_paths: Mapped[list] = mapped_column(JSONType, default=list, nullable=False)
    is_authorized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_method: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    authorized_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    project = relationship("Project", back_populates="authorized_targets")
    verifications = relationship("TargetVerification", back_populates="target", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="target")


class TargetVerification(Base, TimestampMixin):
    __tablename__ = "target_verifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("authorized_targets.id", ondelete="CASCADE"), nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(64), nullable=False)  # dns_txt, http_well_known, explicit_authorization
    challenge_token: Mapped[str] = mapped_column(String(128), nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verification_details: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    target = relationship("AuthorizedTarget", back_populates="verifications")
