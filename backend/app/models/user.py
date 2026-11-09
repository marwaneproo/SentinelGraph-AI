from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator


def validate_bcrypt_password_length(password: str) -> str:
    if len(password.encode("utf-8")) > 72:
        raise ValueError("Password must be no more than 72 UTF-8 bytes.")
    return password

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    full_name: str
    role: str = Field("Viewer", description="Role: Administrator, Security Analyst, Viewer")
    is_active: bool = True

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

    @field_validator("password")
    @classmethod
    def enforce_bcrypt_byte_limit(cls, password: str) -> str:
        return validate_bcrypt_password_length(password)

class UserResponse(UserBase):
    id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None

class LoginRequest(BaseModel):
    username: str
    password: str = Field(..., min_length=1, max_length=72)

    @field_validator("password")
    @classmethod
    def enforce_bcrypt_byte_limit(cls, password: str) -> str:
        return validate_bcrypt_password_length(password)

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str
    expires_in: int

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
