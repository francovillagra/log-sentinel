"""El administrador inicial: se crea una sola vez, con una contraseña que pase la validación."""
import pytest

from api.main import ensure_admin_user
from api.services.auth_service import verify_password
from tests.api.conftest import ADMIN_EMAIL, ADMIN_PASSWORD

pytestmark = pytest.mark.db


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ADMIN_EMAIL", ADMIN_EMAIL)
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PASSWORD)


async def _users(pool):
    async with pool.acquire() as conn:
        return await conn.fetch("SELECT email, password_hash FROM users")


async def test_creates_the_admin_when_the_table_is_empty(pool):
    await ensure_admin_user(pool)
    (row,) = await _users(pool)
    assert row["email"] == ADMIN_EMAIL
    assert row["password_hash"] != ADMIN_PASSWORD and verify_password(ADMIN_PASSWORD, row["password_hash"])


async def test_does_nothing_when_a_user_already_exists_and_needs_no_password(pool, admin, monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD")  # ya creada la cuenta, la contraseña se puede sacar del entorno
    await ensure_admin_user(pool)
    assert len(await _users(pool)) == 1


async def test_an_existing_admin_is_never_overwritten(pool, admin, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "Otra-Contrasena-Larga-77")
    await ensure_admin_user(pool)
    (row,) = await _users(pool)
    assert verify_password(ADMIN_PASSWORD, row["password_hash"])


async def test_a_missing_password_stops_the_start_when_there_is_no_admin(pool, monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD")
    with pytest.raises(RuntimeError, match="ADMIN_PASSWORD"):
        await ensure_admin_user(pool)
    assert await _users(pool) == []


@pytest.mark.parametrize("weak", ["corta", "aaaaaaaaaaaaaaaaaaaa", "change-me-before-deploy", "x" * 80])
async def test_a_weak_password_stops_the_start_and_creates_nothing(pool, monkeypatch, weak):
    monkeypatch.setenv("ADMIN_PASSWORD", weak)
    with pytest.raises(RuntimeError, match="ADMIN_PASSWORD"):
        await ensure_admin_user(pool)
    assert await _users(pool) == []
