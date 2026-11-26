import uuid
from typing import Optional
from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="analyst", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")
