import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import HTTPException, status

from common.email_service import send_account_disabled_email, send_repo_deleted_email
from core.config import REFRESH_TOKEN_EXPIRE_DAYS
from core.database import supabase_client
from service.auth.helper import blacklist_user_session, record_audit_log
from service.profile.helper import invalidate_repo_semantic_cache

logger = logging.getLogger(__name__)


def _require_db() -> None:
    if not supabase_client:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable.")


def _paginate_meta(page: int, limit: int, total: int) -> Dict[str, Any]:
    total_pages = math.ceil(total / limit) if total > 0 else 1
    return {
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


def list_all_users(page: int, limit: int, is_active: Optional[bool] = None) -> Dict[str, Any]:
    _require_db()
    start = (page - 1) * limit
    end = start + limit - 1

    query = supabase_client.table("users").select(
        "id, email, username, role, is_active, auth_provider, created_at",
        count="exact",
    )
    if is_active is not None:
        query = query.eq("is_active", is_active)

    res = query.order("created_at", desc=True).range(start, end).execute()
    total = res.count if res.count is not None else len(res.data or [])
    return {"users": res.data or [], **_paginate_meta(page, limit, total)}


def set_user_active_status(
    admin_id: str,
    target_user_id: str,
    active: bool,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    _require_db()
    if admin_id == target_user_id and not active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot disable your own admin account.")

    user_res = (
        supabase_client.table("users")
        .select("id, email, username, role, is_active")
        .eq("id", target_user_id)
        .limit(1)
        .execute()
    )
    if not user_res.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    target = user_res.data[0]
    supabase_client.table("users").update({"is_active": active}).eq("id", target_user_id).execute()

    email_sent = False
    if not active:
        # Invalidate existing sessions immediately alongside per-request DB is_active check
        exp = int(datetime.now(timezone.utc).timestamp()) + REFRESH_TOKEN_EXPIRE_DAYS * 86400
        blacklist_user_session(target_user_id, exp)
        email_sent = send_account_disabled_email(
            target["email"],
            target.get("username"),
            reason or "Account disabled by administrator.",
        )

    record_audit_log(
        actor_id=admin_id,
        action="user_enabled" if active else "user_disabled",
        target_type="user",
        target_id=target_user_id,
        details={"email": target["email"], "reason": reason} if reason else {"email": target["email"]},
    )
    return {
        "message": f"User {target.get("username")} & id {target_user_id} {'enabled' if active else 'disabled'}.",
        "user_id": target_user_id,
        "is_active": active,
        "email_sent": email_sent if not active else None,
    }


def list_all_repositories(page: int, limit: int, status_filter: Optional[str] = None) -> Dict[str, Any]:
    _require_db()
    start = (page - 1) * limit
    end = start + limit - 1

    query = supabase_client.table("repo_registry").select(
        "id, user_id, repo_url, source_type, repo_hash, status, last_ingested_at",
        count="exact",
    )
    if status_filter:
        query = query.eq("status", status_filter)

    res = query.order("last_ingested_at", desc=True).range(start, end).execute()
    total = res.count if res.count is not None else len(res.data or [])
    return {"repositories": res.data or [], **_paginate_meta(page, limit, total)}


def admin_delete_repository(admin_id: str, repo_id: str, reason: str) -> Dict[str, Any]:
    """TRD §5: Delete repository with mandatory reason and email the uploader."""
    _require_db()
    repo_res = (
        supabase_client.table("repo_registry")
        .select("id, user_id, repo_url, source_type")
        .eq("id", repo_id)
        .limit(1)
        .execute()
    )
    if not repo_res.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found.")

    repo = repo_res.data[0]
    uploader_id = repo["user_id"]
    repo_url = repo["repo_url"]

    user_res = supabase_client.table("users").select("email").eq("id", uploader_id).limit(1).execute()
    uploader_email = user_res.data[0]["email"] if user_res.data else None

    try:
        supabase_client.table("chunk_registry").delete().eq("repo_id", repo_id).execute()
        supabase_client.table("chunks").delete().eq("repo_id", repo_id).execute()
        supabase_client.table("repo_registry").delete().eq("id", repo_id).execute()
    except Exception as exc:
        logger.error(f"Admin failed to delete repo {repo_id}: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete repository.")

    invalidate_repo_semantic_cache(uploader_id, repo_id)

    email_sent = False
    if uploader_email:
        email_sent = send_repo_deleted_email(uploader_email, repo_url, reason)

    record_audit_log(
        actor_id=admin_id,
        action="repo_deleted_by_admin",
        target_type="repository",
        target_id=repo_id,
        details={"repo_url": repo_url, "uploader_id": uploader_id, "reason": reason},
    )
    return {
        "message": f"Repository {repo_id} deleted.",
        "repo_id": repo_id,
        "email_sent": email_sent,
    }


def get_platform_stats() -> Dict[str, Any]:
    """TRD §5 & BRD BR-ADM-08: Users, repos, queries, cache hits, tokens, and iteration-limit hits."""
    _require_db()

    users_total = supabase_client.table("users").select("id", count="exact").execute().count or 0
    users_active = supabase_client.table("users").select("id", count="exact").eq("is_active", True).execute().count or 0
    repos_total = supabase_client.table("repo_registry").select("id", count="exact").execute().count or 0
    repos_completed = (
        supabase_client.table("repo_registry").select("id", count="exact").eq("status", "completed").execute().count or 0
    )

    queries_total = (
        supabase_client.table("chat_messages")
        .select("id", count="exact")
        .eq("role", "assistant")
        .execute()
        .count
        or 0
    )
    cache_hits = (
        supabase_client.table("chat_messages")
        .select("id", count="exact")
        .eq("role", "assistant")
        .eq("from_cache", True)
        .execute()
        .count
        or 0
    )
    limit_hits = (
        supabase_client.table("chat_messages")
        .select("id", count="exact")
        .eq("role", "assistant")
        .eq("limit_reached", True)
        .execute()
        .count
        or 0
    )

    usage_res = supabase_client.table("usage_events").select("model, role, tokens_in, tokens_out").execute()
    total_tokens_in = 0
    total_tokens_out = 0
    by_model: Dict[str, Dict[str, int]] = {}
    for row in usage_res.data or []:
        t_in = int(row.get("tokens_in") or 0)
        t_out = int(row.get("tokens_out") or 0)
        total_tokens_in += t_in
        total_tokens_out += t_out
        model = row.get("model") or "unknown"
        bucket = by_model.setdefault(model, {"calls": 0, "tokens_in": 0, "tokens_out": 0})
        bucket["calls"] += 1
        bucket["tokens_in"] += t_in
        bucket["tokens_out"] += t_out

    return {
        "users": {"total": users_total, "active": users_active, "disabled": users_total - users_active},
        "repositories": {"total": repos_total, "completed": repos_completed},
        "queries": {
            "total": queries_total,
            "cache_hits": cache_hits,
            "cache_hit_rate": round((cache_hits / queries_total), 4) if queries_total else 0.0,
            "iteration_limit_hits": limit_hits,
        },
        "tokens": {"total_in": total_tokens_in, "total_out": total_tokens_out, "by_model": by_model},
    }


def list_audit_logs(
    page: int,
    limit: int,
    action: Optional[str] = None,
    target_type: Optional[str] = None,
) -> Dict[str, Any]:
    _require_db()
    start = (page - 1) * limit
    end = start + limit - 1

    query = supabase_client.table("audit_logs").select("*", count="exact")
    if action:
        query = query.eq("action", action)
    if target_type:
        query = query.eq("target_type", target_type)

    res = query.order("created_at", desc=True).range(start, end).execute()
    total = res.count if res.count is not None else len(res.data or [])
    return {"audit_logs": res.data or [], **_paginate_meta(page, limit, total)}