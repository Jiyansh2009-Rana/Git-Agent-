from typing import Optional
from fastapi import APIRouter, Body, Depends, Query

from common.models import AdminDeleteRepoRequest, DisableUserRequest, TokenClaims
from core.security import require_admin, verify_csrf
from service.admin.helper import (
    admin_delete_repository,
    get_platform_stats,
    list_all_repositories,
    list_all_users,
    list_audit_logs,
    set_user_active_status,
)

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])


@router.get("/users")
async def get_users(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    is_active: Optional[bool] = Query(None),
    _: TokenClaims = Depends(require_admin),
):
    return list_all_users(page, limit, is_active)


@router.patch("/users/{user_id}/disable", dependencies=[Depends(verify_csrf)])
async def disable_user(
    user_id: str,
    payload: Optional[DisableUserRequest] = Body(default=None),
    current_admin: TokenClaims = Depends(require_admin),
):
    reason = payload.reason if payload else None
    return set_user_active_status(current_admin.user_id, user_id, active=False, reason=reason)


@router.patch("/users/{user_id}/enable", dependencies=[Depends(verify_csrf)])
async def enable_user(
    user_id: str,
    current_admin: TokenClaims = Depends(require_admin),
):
    return set_user_active_status(current_admin.user_id, user_id, active=True)


@router.get("/repos")
async def get_repos(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    _: TokenClaims = Depends(require_admin),
):
    return list_all_repositories(page, limit, status)


@router.delete("/repos/{repo_id}", dependencies=[Depends(verify_csrf)])
async def delete_repo(
    repo_id: str,
    payload: AdminDeleteRepoRequest,
    current_admin: TokenClaims = Depends(require_admin),
):
    return admin_delete_repository(current_admin.user_id, repo_id, payload.reason)


@router.get("/stats")
async def get_stats(_: TokenClaims = Depends(require_admin)):
    return get_platform_stats()


@router.get("/audit-logs")
async def get_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    action: Optional[str] = Query(None),
    target_type: Optional[str] = Query(None),
    _: TokenClaims = Depends(require_admin),
):
    return list_audit_logs(page, limit, action, target_type)