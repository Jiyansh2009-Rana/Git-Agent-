from datetime import datetime, timezone
from fastapi import APIRouter, Depends,Query
from common.models import AuthProvider, ProfileUpdateRequest, Role, TokenClaims, UserInfo
from core.security import require_user, verify_csrf
from service.profile.helper import (
    delete_own_repository,
    list_user_repositories,
    get_user_profile,
    update_user_profile,
)
router = APIRouter(prefix="/api/v1/profile", tags=["Profile"])

def _to_user_info(row: dict) -> UserInfo:
    return UserInfo(
        user_id=row["id"],
        email=row["email"],
        username=row.get("username") or row["email"].split("@")[0],
        role=Role(row["role"]),
        is_active=bool(row.get("is_active", True)),
        auth_provider=AuthProvider(row.get("auth_provider", "email")),
        created_at=str(row.get("created_at") or datetime.now(timezone.utc).isoformat()),
    )

@router.get("", response_model=UserInfo)
async def get_profile(current_user: TokenClaims = Depends(require_user)):
    """Replaces /auth/me: returns the authenticated user's profile."""
    row = get_user_profile(current_user.user_id)
    return _to_user_info(row)

@router.patch("", response_model=UserInfo, dependencies=[Depends(verify_csrf)])
async def update_profile(
    payload: ProfileUpdateRequest,
    current_user: TokenClaims = Depends(require_user),
):
    row = update_user_profile(current_user.user_id, payload.username)
    return _to_user_info(row)

@router.get("/repos")
async def get_my_repos(
    page: int = Query(1, ge=1),
    limit: int = Query(15, ge=1, le=100),
    current_user: TokenClaims = Depends(require_user),
):
    """Fetch authenticated user's ingested repositories (15 per page by default)."""
    return list_user_repositories(current_user.user_id, page=page, limit=limit)


@router.delete("/repos/{repo_id}", dependencies=[Depends(verify_csrf)])
async def delete_my_repo(
    repo_id: str,
    current_user: TokenClaims = Depends(require_user),
):
    """TRD §5: Delete own repository with its chunks and registry rows."""
    return delete_own_repository(current_user.user_id, repo_id)