from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.database.session import get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.auth import (
    RefreshTokenRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: UserRegisterRequest, request: Request, db: Session = Depends(get_db)):
    exists = (
        db.query(User)
        .filter(or_(User.email == payload.email.lower(), User.username == payload.username))
        .first()
    )
    if exists:
        raise HTTPException(status_code=400, detail="Email or username is already registered.")

    # First user becomes admin; subsequent self-registrations are analyst
    is_first_user = db.query(User).count() == 0
    role = "admin" if is_first_user else "analyst"

    user = User(
        email=payload.email.lower(),
        username=payload.username,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.flush()
    db.add(
        AuditLog(
            user_id=user.id,
            action="user_registered",
            resource_type="user",
            resource_id=user.id,
            ip_address=request.client.host if request.client else None,
            details={"role": role},
        )
    )
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(payload: UserLoginRequest, request: Request, db: Session = Depends(get_db)):
    ident = payload.email_or_username.strip()
    user = (
        db.query(User)
        .filter(or_(User.email == ident.lower(), User.username == ident))
        .first()
    )
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled.")

    db.add(
        AuditLog(
            user_id=user.id,
            action="user_login",
            resource_type="user",
            resource_id=user.id,
            ip_address=request.client.host if request.client else None,
            details={"username": user.username},
        )
    )
    db.commit()

    return TokenResponse(
        access_token=create_access_token(user.id, user.role),
        refresh_token=create_refresh_token(user.id, user.role),
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(payload: RefreshTokenRequest, db: Session = Depends(get_db)):
    decoded = decode_token(payload.refresh_token)
    if not decoded or decoded.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")

    user = db.query(User).filter(User.id == decoded.get("sub")).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not active.")

    return TokenResponse(
        access_token=create_access_token(user.id, user.role),
        refresh_token=create_refresh_token(user.id, user.role),
    )
