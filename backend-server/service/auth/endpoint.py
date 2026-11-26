from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse

from core.config import FRONTEND_URL, REFRESH_TOKEN_EXPIRE_DAYS
from core.database import redis_client, supabase_client
from core.security import (
    clear_auth_cookies,
    create_access_token,
    create_refresh_token,
    decode_jwt_token,
    get_current_user,
    set_auth_cookies,
    verify_csrf,
)
from service.auth.helper import (
    authenticate_email_user,
    blacklist_user_session,
    build_google_oauth_url,
    handle_google_callback,
    initiate_forgot_password,
    initiate_signup_otp,
    record_audit_log,
    resend_otp,
    reset_user_password,
    verify_signup_otp,
)
from common.models import (
    AuthProvider,
    AuthResponse,
    ForgotPasswordRequest,
    ResendOtpRequest,
    ResetPasswordRequest,
    Role,
    TokenClaims,
    UserInfo,
    UserLogin,
    UserSignup,
    VerifyOtpRequest,
)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _to_user_info(row: dict) -> UserInfo:
    return UserInfo(
        user_id=row["id"],
        email=row["email"],
        username=row.get("username"),
        role=Role(row["role"]),
        is_active=bool(row.get("is_active", True)),
        auth_provider=AuthProvider(row.get("auth_provider", "email")),
        created_at=str(row.get("created_at") or datetime.now(timezone.utc).isoformat()),
    )


@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(payload: UserSignup, request: Request):
    return initiate_signup_otp(payload, _client_ip(request))


@router.post("/verify-otp", status_code=status.HTTP_201_CREATED)
async def verify_otp(payload: VerifyOtpRequest, request: Request):
    return verify_signup_otp(payload.email, payload.otp, _client_ip(request))


@router.post("/resend-otp")
async def resend_otp_endpoint(payload: ResendOtpRequest, request: Request):
    return resend_otp(payload.email, payload.purpose, _client_ip(request))


@router.post("/login", response_model=AuthResponse)
async def login(payload: UserLogin, request: Request, response: Response):
    ip = _client_ip(request)
    user = authenticate_email_user(payload.email, payload.password, ip)

    access_token = create_access_token(
        user_id=user["id"],
        email=user["email"],
        username=user.get("username"),
        role=Role(user["role"]),
    )
    refresh_token = create_refresh_token(user_id=user["id"])
    set_auth_cookies(response, access_token, refresh_token)

    record_audit_log(user["id"], "login", "user", user["id"], {"provider": "email", "ip": ip})
    return AuthResponse(message="Login successful.", user=_to_user_info(user))


@router.get("/google")
async def google_login():
    return RedirectResponse(url=build_google_oauth_url(), status_code=status.HTTP_302_FOUND)


@router.get("/google/callback")
async def google_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
):
    user = await handle_google_callback(code=code, state=state)
    access_token = create_access_token(
        user_id=user["id"],
        email=user["email"],
        username=user.get("username"),
        role=Role(user["role"]),
    )
    refresh_token = create_refresh_token(user_id=user["id"])

    record_audit_log(
        user["id"],
        "login",
        "user",
        user["id"],
        {"provider": "google", "ip": _client_ip(request)},
    )
    redirect = RedirectResponse(url=f"{FRONTEND_URL}/chat", status_code=status.HTTP_302_FOUND)
    set_auth_cookies(redirect, access_token, refresh_token)
    return redirect


@router.post("/refresh", dependencies=[Depends(verify_csrf)])
async def refresh(
    response: Response,
    refresh_token: Optional[str] = Cookie(None, alias="refresh_token"),
):
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token missing.")

    payload = decode_jwt_token(refresh_token)
    if payload.get("type") != "refresh" or not payload.get("sub"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")

    user_id = payload["sub"]
    if redis_client:
        revoked_at = redis_client.get(f"blacklist:{user_id}")
        if revoked_at and int(payload.get("iat", 0)) <= int(revoked_at):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session invalidated.")

    if not supabase_client:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable.")

    res = (
        supabase_client.table("users")
        .select("id, email, username, role, is_active")
        .eq("id", user_id)
        .limit(1)
        .execute()
    )
    if not res.data or not res.data[0].get("is_active", False):
        clear_auth_cookies(response)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled or missing.")

    user = res.data[0]
    new_access_token = create_access_token(
        user_id=user["id"],
        email=user["email"],
        username=user.get("username"),
        role=Role(user["role"]),
    )
    set_auth_cookies(response, new_access_token)
    return {"message": "Access token refreshed."}


@router.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest, request: Request):
    return initiate_forgot_password(payload.email, _client_ip(request))


@router.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest, request: Request):
    return reset_user_password(payload.email, payload.otp, payload.new_password, _client_ip(request))


@router.post("/logout", dependencies=[Depends(verify_csrf)])
async def logout(response: Response, current_user: TokenClaims = Depends(get_current_user)):
    exp = int(datetime.now(timezone.utc).timestamp()) + REFRESH_TOKEN_EXPIRE_DAYS * 86400
    blacklist_user_session(current_user.user_id, exp)
    clear_auth_cookies(response)
    return {"message": "Logged out successfully."}
