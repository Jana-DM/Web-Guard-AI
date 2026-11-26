from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.permissions import UserRole, require_min_role
from app.core.security import decode_token
from app.database.session import get_db
from app.models.user import User

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
        )

    payload = decode_token(credentials.credentials)
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
        )

    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or inactive.",
        )
    return user


def require_analyst(current_user: User = Depends(get_current_user)) -> User:
    require_min_role(current_user.role, UserRole.ANALYST)
    return current_user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    require_min_role(current_user.role, UserRole.ADMIN)
    return current_user
