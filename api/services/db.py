import os
import ssl
from typing import Optional

import asyncpg

_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    """
    Lazy singleton: create the asyncpg connection pool on first call.

    DATABASE_URL must be the Supabase *session pooler* connection string.
    SSL is provided as an ssl.SSLContext keyword arg (NOT as a URL parameter),
    which is what asyncpg expects against Supabase.
    """
    global _pool
    if _pool is None:
        dsn = os.environ.get("DATABASE_URL")
        if not dsn:
            raise RuntimeError("DATABASE_URL is not configured")
        ssl_ctx = ssl.create_default_context()
        _pool = await asyncpg.create_pool(
            dsn=dsn,
            ssl=ssl_ctx,
            min_size=1,
            max_size=5,
        )
    return _pool
