from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import bcrypt
import jwt

from app.config import get_settings


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except ValueError:
        return False


def create_token(subject: str, role: str, expires_delta: timedelta, token_type: str = "access") -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def create_access_token(subject: str, role: str) -> str:
    settings = get_settings()
    return create_token(
        subject=subject,
        role=role,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access",
    )


def create_refresh_token(subject: str, role: str) -> str:
    settings = get_settings()
    return create_token(
        subject=subject,
        role=role,
        expires_delta=timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES),
        token_type="refresh",
    )


def decode_token(token: str) -> Optional[dict[str, Any]]:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
