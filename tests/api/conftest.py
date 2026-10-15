"""
Pruebas de la API de Log-Sentinel.

Usan PostgreSQL real: definí TEST_DATABASE_URL con una base descartable cuyo nombre incluya "test" y el esquema de
`schema.sql` aplicado. Redis se reemplaza por un doble en memoria (no hace falta un servidor).
"""
import os
import re
import uuid
from urllib.parse import urlsplit

import pytest
import pytest_asyncio

# Los secretos de prueba tienen que pasar la misma validación que en producción.
os.environ.setdefault("JWT_SECRET", "test-only-jwt-secret-" + uuid.uuid4().hex)
os.environ.setdefault("INGEST_API_KEY", "test-only-ingest-key-" + uuid.uuid4().hex)
os.environ["BCRYPT_ROUNDS"] = "4"  # rápido; la fuerza real se configura en producción
os.environ["CORS_ORIGINS"] = "http://localhost:3000"
for name in ("DEBUG", "TRUSTED_PROXY_COUNT", "MAX_REQUEST_BYTES", "MAX_WS_CONNECTIONS", "DATABASE_SSL_MODE",
             "DATABASE_SSL_CA", "BCRYPT_CONCURRENCY", "BCRYPT_MAX_PENDING"):
    os.environ.pop(name, None)

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
if TEST_DATABASE_URL and not re.search(r"test", urlsplit(TEST_DATABASE_URL).path, re.IGNORECASE):
    raise RuntimeError('TEST_DATABASE_URL tiene que apuntar a una base descartable cuyo nombre incluya "test".')

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "Correct-Horse-Battery-9"
INGEST_KEY = os.environ["INGEST_API_KEY"]


def pytest_collection_modifyitems(config, items):
    if TEST_DATABASE_URL:
        return
    skip = pytest.mark.skip(reason="falta TEST_DATABASE_URL (PostgreSQL de pruebas)")
    for item in items:
        if "db" in item.keywords:
            item.add_marker(skip)


class FakeRedis:
    """Lo mínimo de redis.asyncio que usa la API: xadd / xread / aclose."""

    def __init__(self) -> None:
        self.entries: list[tuple[str, dict]] = []

    async def xadd(self, key, fields, maxlen=None, approximate=True):
        entry_id = f"{len(self.entries) + 1}-0"
        self.entries.append((entry_id, dict(fields)))
        return entry_id

    async def xread(self, streams, count=None, block=None):
        return []

    async def aclose(self) -> None:
        pass


@pytest_asyncio.fixture
async def pool():
    import asyncpg

    pool = await asyncpg.create_pool(TEST_DATABASE_URL, min_size=1, max_size=4)
    async with pool.acquire() as conn:
        await conn.execute("TRUNCATE TABLE alerts, users")
    yield pool
    await pool.close()


@pytest.fixture(autouse=True)
def _fresh_limiters():
    from api.ratelimit import reset_all_limiters

    reset_all_limiters()
    yield
    reset_all_limiters()


def make_app(pool=None, redis=None):
    """La app sin lifespan (no se conecta a Redis ni a la base): se le pone el estado a mano."""
    from api.main import build_engine, create_app

    app = create_app(with_lifespan=False)
    app.state.engine = build_engine()
    app.state.redis = redis if redis is not None else FakeRedis()
    app.state.db_pool = pool
    return app


@pytest_asyncio.fixture
async def app(pool):
    return make_app(pool)


@pytest_asyncio.fixture
async def client(app):
    import httpx

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def nodb_client():
    """Cliente contra la app sin base de datos: sirve para todo lo que no la toca (cabeceras, CORS, autenticación de
    la ingesta). Las excepciones no atrapadas no se re-lanzan: se ve la respuesta 500 que recibiría un cliente."""
    import httpx

    transport = httpx.ASGITransport(app=make_app(None), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def admin(pool):
    """Crea el administrador en la base y devuelve (email, contraseña)."""
    from api.services.auth_service import hash_password

    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2)", ADMIN_EMAIL, hash_password(ADMIN_PASSWORD)
        )
    return ADMIN_EMAIL, ADMIN_PASSWORD


def bearer(email: str = ADMIN_EMAIL) -> dict:
    from api.services.auth_service import create_access_token

    return {"Authorization": f"Bearer {create_access_token(email)}"}
