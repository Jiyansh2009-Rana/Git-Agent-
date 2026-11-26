import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import HTTPException, status

from core.database import redis_client, supabase_client
from service.auth.helper import record_audit_log

logger = logging.getLogger(__name__)


def _require_db() -> None:
    if not supabase_client:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable.")


def invalidate_repo_semantic_cache(user_id: str, repo_id: str) -> None:
    """TRD §8.2 & §12: Invalidate user/repo semantic cache entries on deletion."""
    if not redis_client:
        return
    try:
        pattern = f"semcache:{user_id}:{repo_id}:*"
        keys = list(redis_client.scan_iter(match=pattern, count=200))
        if keys:
            redis_client.delete(*keys)
    except Exception as exc:
        logger.warning(f"Failed invalidating semantic cache for {user_id}/{repo_id}: {exc}")


def get_user_profile(user_id: str) -> Dict[str, Any]:
    _require_db()
    res = (
        supabase_client.table("users")
        .select("id, email, username, role, is_active, auth_provider, created_at")
        .eq("id", user_id)
        .limit(1)
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return res.data[0]
def update_user_profile(user_id: str, username: str) -> Dict[str, Any]:
    _require_db()
    cleaned = username.strip()
    if len(cleaned) < 4:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username must be at least 4 characters.")
    res = (
        supabase_client.table("users")
        .update({"username": cleaned})
        .eq("id", user_id)
        .execute()
    )
    if not res.data:
        return get_user_profile(user_id)
    return res.data[0]

def list_user_repositories(
    user_id: str,
    page: int = 1,
    limit: int = 15,
) -> Dict[str, Any]:
    """
    Fetch all repositories owned by the user with pagination (default 15 rows per page).
    """
    _require_db()
    start = (page - 1) * limit
    end = start + limit - 1

    try:
        res = (
            supabase_client.table("repo_registry")
            .select(
                "id, repo_url, source_type, status, last_ingested_at",
                count="exact",
            )
            .eq("user_id", user_id)
            .order("last_ingested_at", desc=True)
            .range(start, end)
            .execute()
        )
    except Exception as exc:
        logger.error(f"Failed listing repositories for user {user_id}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch repositories.",
        )

    total = res.count if res.count is not None else len(res.data or [])
    total_pages = math.ceil(total / limit) if total > 0 else 1

    return {
        "repositories": res.data or [],
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


def delete_own_repository(user_id: str, repo_id: str) -> Dict[str, str]:
    """
    TRD §5, §8.2 & §9.3:
    Delete own repository with its chunks and registry rows.
    Chats and chat_messages are preserved so old chats stay readable.
    """
    _require_db()
    repo_res = (
        supabase_client.table("repo_registry")
        .select("id, user_id, repo_url")
        .eq("id", repo_id)
        .eq("user_id", user_id)
        .limit(1)
        .execute()
    )
    if not repo_res.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found.")

    repo = repo_res.data[0]
    try:
        supabase_client.table("chunk_registry").delete().eq("repo_id", repo_id).eq("user_id", user_id).execute()
        supabase_client.table("chunks").delete().eq("repo_id", repo_id).eq("user_id", user_id).execute()
        supabase_client.table("repo_registry").delete().eq("id", repo_id).eq("user_id", user_id).execute()
    except Exception as exc:
        logger.error(f"Failed deleting repository {repo_id} for user {user_id}: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete repository.")

    invalidate_repo_semantic_cache(user_id, repo_id)
    record_audit_log(
        actor_id=user_id,
        action="repo_deleted_by_owner",
        target_type="repository",
        target_id=repo_id,
        details={"repo_url": repo.get("repo_url"), "deleted_at": datetime.now(timezone.utc).isoformat()},
    )
    return {"message": f"Repository {repo_id} and its indexed chunks have been deleted."}