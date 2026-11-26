import uuid
from typing import Optional
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin


class Project(Base, TimestampMixin):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    environment: Mapped[str] = mapped_column(String(50), default="production", nullable=False)

    owner = relationship("User", back_populates="projects")
    authorized_targets = relationship("AuthorizedTarget", back_populates="project", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="project", cascade="all, delete-orphan")
