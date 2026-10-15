"""
Configuración sensible de la API.

Los secretos se validan al arrancar: un despliegue con el valor de ejemplo del `.env.example` (o uno corto o
repetitivo) falla de entrada con un mensaje claro, en lugar de quedar abierto para cualquiera que haya leído
el ejemplo. Los demás valores se leen del entorno en cada uso, así las pruebas pueden cambiarlos.
"""
import os

# Fragmentos típicos de los valores de ejemplo (".env.example", tutoriales).
_EXAMPLE_MARKERS = (
    "change-me", "change_me", "changeme", "example", "placeholder", "your-secret", "your_secret",
    "secret-here", "secret_here", "supersecret", "super-secret", "before-deploy",
)
_GENERATE_HINT = 'Generá uno con: python -c "import secrets; print(secrets.token_hex(32))"'


def _is_weak(value: str, min_length: int) -> bool:
    return (
        len(value) < min_length
        or len(set(value)) < 8  # "aaaa...", "abababab..."
        or any(marker in value.lower() for marker in _EXAMPLE_MARKERS)
    )


def require_secret(name: str, min_length: int = 32) -> str:
    value = os.environ.get(name, "")
    if _is_weak(value, min_length):
        raise RuntimeError(
            f"{name} tiene que tener al menos {min_length} caracteres, no ser repetitivo ni un valor de ejemplo. "
            + _GENERATE_HINT
        )
    return value


def validate_admin_password(password: str) -> str:
    """Contraseña del administrador inicial: bcrypt solo usa los primeros 72 bytes, y una corta se adivina."""
    if len(password.encode("utf-8")) > 72:
        raise RuntimeError("ADMIN_PASSWORD no puede tener más de 72 bytes (es lo que bcrypt usa).")
    if _is_weak(password, 12) or len(set(password)) < 6:
        raise RuntimeError(
            "ADMIN_PASSWORD tiene que tener al menos 12 caracteres, no ser repetitiva ni un valor de ejemplo."
        )
    return password


def validate_environment() -> None:
    """Se llama al arrancar. Levanta RuntimeError si falta o es débil algún secreto."""
    require_secret("JWT_SECRET")
    require_secret("INGEST_API_KEY")


def _int_env(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except ValueError:
        return default


def allowed_origins() -> list[str]:
    raw = os.environ.get("CORS_ORIGINS", "http://localhost:3000")
    return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]


def docs_enabled() -> bool:
    return os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")


def trusted_proxy_count() -> int:
    """Cuántos proxies de confianza hay delante de la API (Railway = 1). Con 0 se usa la IP del socket."""
    return _int_env("TRUSTED_PROXY_COUNT", 0)


def max_request_bytes() -> int:
    return _int_env("MAX_REQUEST_BYTES", 2_000_000, minimum=1)


def max_ingest_lines() -> int:
    return _int_env("MAX_INGEST_LINES", 1000, minimum=1)


def max_ws_connections() -> int:
    return _int_env("MAX_WS_CONNECTIONS", 50, minimum=1)


def bcrypt_rounds() -> int:
    return _int_env("BCRYPT_ROUNDS", 12, minimum=4)


def bcrypt_concurrency() -> int:
    return _int_env("BCRYPT_CONCURRENCY", 2, minimum=1)


def bcrypt_max_pending() -> int:
    return _int_env("BCRYPT_MAX_PENDING", 32, minimum=1)
