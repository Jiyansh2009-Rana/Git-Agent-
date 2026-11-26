import logging
import redis
from supabase import Client, create_client
from core.config import REDIS_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL
logger = logging.getLogger(__name__)
try:
    supabase_client: Client | None = (
        create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
        if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY
        else None
    )
except Exception as exc:
    logger.warning(f"Supabase initialization failed: {exc}")
    supabase_client = None
try:
    redis_client: redis.Redis | None = redis.from_url(
        REDIS_URL,
        decode_responses=True,
        socket_timeout=3.0,
        socket_connect_timeout=3.0,
    )
except Exception as exc:
    logger.warning(f"Redis initialization failed: {exc}")
    redis_client = None