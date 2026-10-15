"""Los secretos de ejemplo, cortos o repetitivos hacen que la API no arranque."""
import pytest

from api import config


@pytest.mark.parametrize("value", [
    "",                                           # falta
    "short",                                      # corto
    "a" * 64,                                     # repetitivo
    "abababababababababababababababababab",       # repetitivo
    "change-me-before-deploy",                    # el valor del .env.example
    "my-super-secret-value-please-change-me-x",   # contiene "change-me"
    "this-is-an-example-secret-1234567890abcdef", # contiene "example"
])
def test_weak_secrets_are_refused(monkeypatch, value):
    monkeypatch.setenv("JWT_SECRET", value)
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        config.require_secret("JWT_SECRET")


def test_a_strong_secret_is_accepted(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "8f3c1d9a4b7e2f605a8d3c1e9b4f7a20d6c5e8b1a3f4c7d9e0b2a5c8f1e4d7b3")
    assert config.require_secret("JWT_SECRET").startswith("8f3c")


def test_validate_environment_checks_both_secrets(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "8f3c1d9a4b7e2f605a8d3c1e9b4f7a20d6c5e8b1a3f4c7d9e0b2a5c8f1e4d7b3")
    monkeypatch.setenv("INGEST_API_KEY", "change-me-before-deploy")
    with pytest.raises(RuntimeError, match="INGEST_API_KEY"):
        config.validate_environment()


@pytest.mark.parametrize("password", ["admin", "short-pass", "x" * 40, "Password-example-1234", "ñ" * 40])
def test_weak_admin_passwords_are_refused(password):
    with pytest.raises(RuntimeError, match="ADMIN_PASSWORD"):
        config.validate_admin_password(password)


def test_a_reasonable_admin_password_is_accepted():
    assert config.validate_admin_password("Correct-Horse-Battery-9")


async def test_the_app_does_not_start_with_an_example_secret(monkeypatch):
    """El lifespan valida antes de tocar Redis o la base: con el valor del .env.example falla de entrada."""
    from api.main import create_app

    monkeypatch.setenv("INGEST_API_KEY", "change-me-before-deploy")
    app = create_app()
    with pytest.raises(RuntimeError, match="INGEST_API_KEY"):
        async with app.router.lifespan_context(app):
            pass
