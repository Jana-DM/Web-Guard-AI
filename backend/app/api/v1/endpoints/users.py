from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.dependencies import get_current_user, require_admin
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.auth import UserResponse

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/me", response_model=UserResponse)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("", response_model=list[UserResponse])
def list_users(_admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(User).order_by(User.created_at.desc()).all()


@router.get("/audit-logs")
def list_audit_logs(
    limit: int = 50,
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(min(limit, 200)).all()
    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "ip_address": log.ip_address,
            "details": log.details,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]
