import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from fastapi import Cookie, Depends, Header, HTTPException, Response, status
from jose import JWTError, jwt
from passlib.context import CryptContext

from core.config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    COOKIE_SAMESITE,
    COOKIE_SECURE,
    JWT_ALGORITHM,
    JWT_SECRET_KEY,
    REFRESH_TOKEN_EXPIRE_DAYS,
)
from core.database import redis_client, supabase_client
from common.models import Role, TokenClaims

# TRD §6: Argon2 preferred, bcrypt supported
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: Optional[str]) -> bool:
    if not hashed_password:
        return False
    return pwd_context.verify(plain_password, hashed_password)


def hash_otp(email: str, otp: str) -> str:
    """TRD §6: Store OTP hash in Redis, never plain text."""
    msg = f"{email.strip().lower()}:{otp.strip()}".encode("utf-8")
    return hmac.new(JWT_SECRET_KEY.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def create_access_token(user_id: str, email: str, username: str, role: Role) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "username":username,
        "role": role.value,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
        )


def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: Optional[str] = None,
) -> None:
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    if refresh_token is not None:
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite=COOKIE_SAMESITE,
            path="/api/v1/auth",
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        )
    # Double-submit CSRF cookie (readable by Next.js to send back in X-CSRF-Token)
    response.set_cookie(
        key="csrf_token",
        value=secrets.token_urlsafe(32),
        httponly=False,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/api/v1/auth")
    response.delete_cookie("csrf_token", path="/")


def verify_csrf(
    csrf_cookie: Optional[str] = Cookie(None, alias="csrf_token"),
    csrf_header: Optional[str] = Header(None, alias="X-CSRF-Token"),
) -> None:
    """TRD §4 & §13: CSRF protection on cookie-authenticated state-changing requests."""
    if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed.",
        )


def extract_access_token(
    access_token_cookie: Optional[str] = Cookie(None, alias="access_token"),
    authorization: Optional[str] = Header(None),
) -> str:
    if access_token_cookie:
        return access_token_cookie
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required.",
    )


async def get_current_user(token: str = Depends(extract_access_token)) -> TokenClaims:
    payload = decode_jwt_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type.")

    user_id: Optional[str] = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token.")

    # Check Redis revocation blacklist (logout / password reset)
    if redis_client:
        try:
            revoked_at = redis_client.get(f"blacklist:{user_id}")
            if revoked_at and int(payload.get("iat", 0)) <= int(revoked_at):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session has been invalidated. Please log in again.",
                )
        except HTTPException:
            raise
        except Exception:
            pass

    # TRD §6: Every authenticated request checks that the user is active
    if not supabase_client:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable.")

    res = (
        supabase_client.table("users")
        .select("id, email, username , role, is_active")
        .eq("id", user_id)
        .limit(1)
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")

    user_row = res.data[0]
    if not user_row.get("is_active", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been disabled.",
        )

    return TokenClaims(
        user_id=user_row["id"],
        username=user_row["username"],
        email=user_row["email"],
        role=Role(user_row["role"]),
        exp=payload.get("exp"),
        iat=payload.get("iat"),
    )


class RoleChecker:
    def __init__(self, allowed_roles: List[Role]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: TokenClaims = Depends(get_current_user)) -> TokenClaims:
        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions.",
            )
        return current_user


require_user = RoleChecker([Role.USER, Role.ADMIN])
require_admin = RoleChecker([Role.ADMIN])