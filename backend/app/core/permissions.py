from enum import Enum
from fastapi import HTTPException, status


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


ROLE_HIERARCHY = {
    UserRole.VIEWER: 1,
    UserRole.ANALYST: 2,
    UserRole.ADMIN: 3,
}


def require_min_role(user_role: str, required: UserRole) -> None:
    try:
        current = UserRole(user_role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid role.") from exc
    if ROLE_HIERARCHY[current] < ROLE_HIERARCHY[required]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation requires {required.value} permissions.",
        )
