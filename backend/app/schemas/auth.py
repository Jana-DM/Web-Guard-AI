from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class UserRegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    full_name: Optional[str] = Field(default=None, max_length=255)


class UserLoginRequest(BaseModel):
    email_or_username: str = Field(min_length=2, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    username: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}
