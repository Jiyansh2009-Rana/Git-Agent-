import hmac
import json
import logging
import secrets
import string
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, status

from core.config import (
    AUTH_RATE_LIMIT_MAX,
    AUTH_RATE_LIMIT_WINDOW_SECONDS,
    GOOGLE_AUTH_ENDPOINT,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    GOOGLE_TOKEN_ENDPOINT,
    GOOGLE_USERINFO_ENDPOINT,
    OTP_MAX_ATTEMPTS,
    OTP_RESEND_COOLDOWN_SECONDS,
    OTP_TTL_SECONDS,
)
from core.database import redis_client, supabase_client
from core.security import hash_otp, hash_password, verify_password
from common.email_service import send_otp_email
from common.models import AuthProvider, Role, UserSignup

logger = logging.getLogger(__name__)


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def generate_otp(length: int = 6) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(length))


def _require_services(need_redis: bool = True, need_db: bool = True) -> None:
    if need_redis and not redis_client:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Redis unavailable.")
    if need_db and not supabase_client:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable.")


def enforce_rate_limit(scope: str, identifier: str, limit: int = AUTH_RATE_LIMIT_MAX, window: int = AUTH_RATE_LIMIT_WINDOW_SECONDS) -> None:
    """TRD §6 & §13: Fixed-window rate limiter in Redis."""
    if not redis_client:
        return
    key = f"rl:{scope}:{identifier}"
    count = redis_client.incr(key)
    if count == 1:
        redis_client.expire(key, window)
    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again shortly.",
        )


def _enforce_otp_cooldown(purpose: str, email: str) -> None:
    cooldown_key = f"otp_cooldown:{purpose}:{email}"
    if redis_client.exists(cooldown_key):
        ttl = redis_client.ttl(cooldown_key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Please wait {max(ttl, 1)}s before requesting a new OTP.",
        )
    redis_client.setex(cooldown_key, OTP_RESEND_COOLDOWN_SECONDS, "1")


def record_audit_log(
    actor_id: Optional[str],
    action: str,
    target_type: str,
    target_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """TRD §9 & §13: Record login and security events in audit_logs."""
    if not supabase_client:
        return
    try:
        supabase_client.table("audit_logs").insert({
            "id": f"aud_{uuid.uuid4().hex[:12]}",
            "actor_id": actor_id,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "details": details or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as exc:
        logger.warning(f"Failed to write audit log ({action}): {exc}")


def fetch_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    _require_services(need_redis=False, need_db=True)
    res = (
        supabase_client.table("users")
        .select("*")
        .eq("email", normalize_email(email))
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


# ---------------------------------------------------------------------------
# Sign-up & OTP Verification
# ---------------------------------------------------------------------------
def initiate_signup_otp(payload: UserSignup, client_ip: str) -> Dict[str, str]:
    _require_services(need_redis=True, need_db=True)
    email = normalize_email(payload.email)
    enforce_rate_limit("signup:ip", client_ip)
    enforce_rate_limit("signup:email", email, limit=5, window=300)

    if fetch_user_by_email(email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered.")

    _enforce_otp_cooldown("signup", email)

    otp = generate_otp()
    pending_record = {
        "email": email,
        "username": payload.username or email.split("@")[0] ,
        "password_hash": hash_password(payload.password),
        "otp_hash": hash_otp(email, otp),
        "attempts": 0,
    }
    redis_client.setex(f"signup:{email}", OTP_TTL_SECONDS, json.dumps(pending_record))

    try:
        send_otp_email(email, otp, "signup")
    except Exception as exc:
        redis_client.delete(f"signup:{email}")
        logger.error(f"Signup OTP email failed for {email}: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send verification email.")

    return {"message": "OTP sent to email. Please verify within 5 minutes."}


def verify_signup_otp(email: str, provided_otp: str, client_ip: str) -> Dict[str, Any]:
    _require_services(need_redis=True, need_db=True)
    email = normalize_email(email)
    enforce_rate_limit("verify_otp:ip", client_ip)
    enforce_rate_limit("verify_otp:email", email, limit=10, window=300)

    redis_key = f"signup:{email}"
    raw = redis_client.get(redis_key)
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP expired or invalid email.")

    stored = json.loads(raw)
    if not hmac.compare_digest(stored["otp_hash"], hash_otp(email, provided_otp)):
        attempts = stored.get("attempts", 0) + 1
        if attempts >= OTP_MAX_ATTEMPTS:
            redis_client.delete(redis_key)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum OTP attempts exceeded. Please request a new OTP.",
            )
        stored["attempts"] = attempts
        ttl = max(redis_client.ttl(redis_key), 1)
        redis_client.setex(redis_key, ttl, json.dumps(stored))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect OTP.")

    if fetch_user_by_email(email):
        redis_client.delete(redis_key)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered.")

    user_id = f"usr_{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(timezone.utc).isoformat()
    user_row = {
        "id": user_id,
        "email": email,
        "username":stored["username"],
        "password_hash": stored["password_hash"],
        "role": Role.USER.value,
        "is_active": True,
        "auth_provider": AuthProvider.EMAIL.value,
        "created_at": created_at,
    }
    try:
        supabase_client.table("users").insert(user_row).execute()
    except Exception as exc:
        logger.error(f"User insert failed for {email}: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User creation failed.")

    redis_client.delete(redis_key)
    return {"message": "Email verified successfully. You can now log in.", "user_id": user_id, "email": email}


def resend_otp(email: str, purpose: str, client_ip: str) -> Dict[str, str]:
    _require_services(need_redis=True, need_db=True)
    email = normalize_email(email)
    enforce_rate_limit("resend_otp:ip", client_ip)
    enforce_rate_limit("resend_otp:email", email, limit=5, window=300)

    if purpose == "signup":
        redis_key = f"signup:{email}"
        raw = redis_client.get(redis_key)
        if not raw:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No pending signup found. Please sign up again.")
        _enforce_otp_cooldown("signup", email)
        otp = generate_otp()
        stored = json.loads(raw)
        stored["otp_hash"] = hash_otp(email, otp)
        stored["attempts"] = 0
        redis_client.setex(redis_key, OTP_TTL_SECONDS, json.dumps(stored))
    else:
        user = fetch_user_by_email(email)
        if not user or not user.get("is_active", False):
            # Avoid revealing whether an email exists
            return {"message": "If an active account exists, a new OTP has been sent."}
        _enforce_otp_cooldown("reset", email)
        otp = generate_otp()
        redis_client.setex(
            f"reset:{email}",
            OTP_TTL_SECONDS,
            json.dumps({"otp_hash": hash_otp(email, otp), "attempts": 0}),
        )

    try:
        send_otp_email(email, otp, purpose)
    except Exception as exc:
        logger.error(f"Resend OTP failed for {email}: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send OTP email.")

    return {"message": "A new OTP has been sent to your email."}


# ---------------------------------------------------------------------------
# Login & Password Reset
# ---------------------------------------------------------------------------
def authenticate_email_user(email: str, password: str, client_ip: str) -> Dict[str, Any]:
    _require_services(need_redis=False, need_db=True)
    email = normalize_email(email)
    enforce_rate_limit("login:ip", client_ip, limit=15, window=60)
    enforce_rate_limit("login:email", email, limit=10, window=300)

    user = fetch_user_by_email(email)
    if not user or not verify_password(password, user.get("password_hash")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not user.get("is_active", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Your account has been disabled.")

    return user


def initiate_forgot_password(email: str, client_ip: str) -> Dict[str, str]:
    _require_services(need_redis=True, need_db=True)
    email = normalize_email(email)
    enforce_rate_limit("forgot:ip", client_ip)
    enforce_rate_limit("forgot:email", email, limit=5, window=300)

    user = fetch_user_by_email(email)
    if not user or not user.get("is_active", False):
        return {"message": "If an active account exists, an OTP has been sent."}

    _enforce_otp_cooldown("reset", email)
    otp = generate_otp()
    redis_client.setex(
        f"reset:{email}",
        OTP_TTL_SECONDS,
        json.dumps({"otp_hash": hash_otp(email, otp), "attempts": 0}),
    )

    try:
        send_otp_email(email, otp, "reset")
    except Exception as exc:
        logger.error(f"Password reset email failed for {email}: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send reset email.")

    return {"message": "If an active account exists, an OTP has been sent."}


def reset_user_password(email: str, provided_otp: str, new_password: str, client_ip: str) -> Dict[str, str]:
    _require_services(need_redis=True, need_db=True)
    email = normalize_email(email)
    enforce_rate_limit("reset:ip", client_ip)

    redis_key = f"reset:{email}"
    raw = redis_client.get(redis_key)
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP.")

    stored = json.loads(raw)
    if not hmac.compare_digest(stored["otp_hash"], hash_otp(email, provided_otp)):
        attempts = stored.get("attempts", 0) + 1
        if attempts >= OTP_MAX_ATTEMPTS:
            redis_client.delete(redis_key)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum OTP attempts exceeded. Please request a new OTP.",
            )
        stored["attempts"] = attempts
        ttl = max(redis_client.ttl(redis_key), 1)
        redis_client.setex(redis_key, ttl, json.dumps(stored))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect OTP.")

    user = fetch_user_by_email(email)
    if not user or not user.get("is_active", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account unavailable.")

    supabase_client.table("users").update({
        "password_hash": hash_password(new_password),
    }).eq("id", user["id"]).execute()

    redis_client.delete(redis_key)
    # Invalidate any previously issued JWTs
    blacklist_user_session(user["id"], int(datetime.now(timezone.utc).timestamp()) + 86400 * 7)
    record_audit_log(user["id"], "password_reset", "user", user["id"])

    return {"message": "Password reset successfully. You can now log in."}


def blacklist_user_session(user_id: str, exp: Optional[int]) -> None:
    if not redis_client or not exp:
        return
    now_ts = int(datetime.now(timezone.utc).timestamp())
    ttl = exp - now_ts
    if ttl > 0:
        try:
            redis_client.setex(f"blacklist:{user_id}", ttl, str(now_ts))
        except Exception as exc:
            logger.warning(f"Redis blacklist error: {exc}")


# ---------------------------------------------------------------------------
# Google OAuth 2.0 (Authorization Code Flow)
# ---------------------------------------------------------------------------
def build_google_oauth_url() -> str:
    _require_services(need_redis=True, need_db=False)
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Google OAuth is not configured.")

    state = secrets.token_urlsafe(24)
    redis_client.setex(f"oauth_state:{state}", 600, "1")

    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
        "state": state,
    }
    return f"{GOOGLE_AUTH_ENDPOINT}?{urlencode(params)}"


async def handle_google_callback(code: str, state: str) -> Dict[str, Any]:
    _require_services(need_redis=True, need_db=True)
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Google OAuth is not configured.")

    state_key = f"oauth_state:{state}"
    if not state or not redis_client.get(state_key):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OAuth state.")
    redis_client.delete(state_key)

    async with httpx.AsyncClient(timeout=10.0) as client:
        token_res = await client.post(
            GOOGLE_TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
            headers={"Accept": "application/json"},
        )
        if token_res.status_code != 200:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to exchange Google auth code.")

        google_access_token = token_res.json().get("access_token", "")
        userinfo_res = await client.get(
            GOOGLE_USERINFO_ENDPOINT,
            headers={"Authorization": f"Bearer {google_access_token}", "Accept": "application/json"},
        )
        if userinfo_res.status_code != 200:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Failed to fetch Google user profile.")

    profile = userinfo_res.json()
    if not profile.get("email_verified") or not profile.get("email"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Google account email is not verified.")

    email = normalize_email(profile["email"])
    user_display_name: str = (
            profile.get("name")
            or profile.get("given_name")
            or email.split("@")[0]
        ).strip()[:50]
    existing = fetch_user_by_email(email)
    if existing:
        if not existing.get("is_active", False):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Your account has been disabled.")
        return existing

    # Auto-provision new user linked by verified email
    user_row = {
        "id": f"usr_{uuid.uuid4().hex[:12]}",
        "email": email,
        "username":user_display_name,
        "password_hash": hash_password(secrets.token_urlsafe(32)),
        "role": Role.USER.value,
        "is_active": True,
        "auth_provider": AuthProvider.GOOGLE.value,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    res = supabase_client.table("users").insert(user_row).execute()
    return res.data[0] if res.data else user_row