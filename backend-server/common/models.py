from enum import Enum
from typing import Literal, Optional
from pydantic import BaseModel, EmailStr, Field


class Role(str, Enum):
    USER = "user"
    ADMIN = "admin"


class AuthProvider(str, Enum):
    EMAIL = "email"
    GOOGLE = "google"


class UserSignup(BaseModel):
    email: EmailStr
    username: str =Field(..., min_length=4, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)


class VerifyOtpRequest(BaseModel):
    email: EmailStr
    otp: str = Field(..., pattern=r"^\d{6}$")


class ResendOtpRequest(BaseModel):
    email: EmailStr
    purpose: Literal["signup", "reset"] = "signup"


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str = Field(..., pattern=r"^\d{6}$")
    new_password: str = Field(..., min_length=8, max_length=128)


class TokenClaims(BaseModel):
    user_id: str
    email: str
    username: Optional[str] = None
    role: Role
    exp: Optional[int] = None
    iat: Optional[int] = None


class UserInfo(BaseModel):
    user_id: str
    email: EmailStr
    username: Optional[str] = None
    role: Role
    is_active: bool
    auth_provider: AuthProvider
    created_at: str


class AuthResponse(BaseModel):
    message: str
    user: UserInfo


class ProfileUpdateRequest(BaseModel):
    username: str = Field(..., min_length=4, max_length=50)


class DisableUserRequest(BaseModel):
    reason: str = Field(
        default="Account disabled by administrator.",
        min_length=3,
        max_length=500,
    )


class AdminDeleteRepoRequest(BaseModel):
    reason: str = Field(..., min_length=5, max_length=500)


class PaginationMeta(BaseModel):
    page: int
    limit: int
    total: int
    total_pages: int
    has_next: bool
    has_prev: bool