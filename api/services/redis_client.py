import os
from typing import Optional

import redis.asyncio as aioredis

_client: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    """Lazy singleton: create the async Redis client on first call."""
    global _client
    if _client is None:
        url = (
            os.environ.get("UPSTASH_REDIS_URL")
            or os.environ.get("REDIS_PRIVATE_URL")
            or os.environ.get("REDIS_URL")
            or "redis://localhost:6379"
        )
        _client = aioredis.from_url(url, decode_responses=True)
    return _client
