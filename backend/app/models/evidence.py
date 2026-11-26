import uuid
from sqlalchemy import Boolean, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, JSONType, TimestampMixin


class EvidenceRecord(Base, TimestampMixin):
    __tablename__ = "evidence_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vulnerability_id: Mapped[str] = mapped_column(String(36), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)  # ast_match, http_header, tls_cert, version_range, dependency_lock, bandit_rule
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    raw_artifact: Mapped[dict] = mapped_column(JSONType, default=dict, nullable=False)
    is_verifiable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    weight: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="evidence_records")
