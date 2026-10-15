import asyncio
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional, TypeVar

import bcrypt
import jwt

from api.config import bcrypt_concurrency, bcrypt_max_pending, bcrypt_rounds

_ALGORITHM = "HS256"
_TOKEN_TTL_HOURS = 24
_ISSUER = "log-sentinel"
_AUDIENCE = "log-sentinel-dashboard"
_REQUIRED_CLAIMS = ["exp", "iat", "sub", "iss", "aud"]


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt (includes a generated salt)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=bcrypt_rounds())).decode("utf-8")


# Hash de una contraseña cualquiera con el costo vigente: comprobar contra él tarda lo mismo que contra un usuario
# real, así un correo inexistente no se distingue por el tiempo de respuesta.
_dummy_hashes: dict[int, str] = {}


def _dummy_hash() -> str:
    rounds = bcrypt_rounds()
    if rounds not in _dummy_hashes:
        _dummy_hashes[rounds] = hash_password("password-for-timing-equalization")
    return _dummy_hashes[rounds]


def verify_password(plain: str, hashed: Optional[str]) -> bool:
    """Compara con bcrypt. Si `hashed` es None (usuario inexistente) hace el mismo trabajo y devuelve False."""
    try:
        matches = bcrypt.checkpw(plain.encode("utf-8"), (hashed or _dummy_hash()).encode("utf-8"))
    except (ValueError, TypeError):  # p. ej. más de 72 bytes con bcrypt >= 5
        return False
    return matches and hashed is not None


# ── bcrypt fuera del hilo principal ──────────────────────────────────────────────────────────────────────────────
# Un hash tarda ~250 ms de CPU. En el hilo del servidor frena todo lo demás (WebSocket, ingesta, /health): bastaba
# con mandar logins en paralelo para dejar la API sin respuesta. Corre en hilos propios (bcrypt suelta el GIL), con
# un tope de trabajos a la vez y un tope de pedidos esperando.

T = TypeVar("T")


class PasswordWorkBusy(Exception):
    """Hay demasiados trabajos de contraseña esperando: se rechaza el pedido en vez de acumularlo."""


_executor: Optional[ThreadPoolExecutor] = None
_pending = 0


def _pool() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=bcrypt_concurrency(), thread_name_prefix="bcrypt")
    return _executor


async def _off_the_loop(func: Callable[..., T], *args: object) -> T:
    global _pending
    if _pending >= bcrypt_max_pending():
        raise PasswordWorkBusy()
    _pending += 1
    try:
        return await asyncio.get_running_loop().run_in_executor(_pool(), func, *args)
    finally:
        _pending -= 1


async def verify_password_async(plain: str, hashed: Optional[str]) -> bool:
    return await _off_the_loop(verify_password, plain, hashed)


async def hash_password_async(plain: str) -> str:
    return await _off_the_loop(hash_password, plain)


def _secret() -> str:
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET is not configured")
    return secret


def create_access_token(email: str) -> str:
    """Issue a signed JWT for the given email, valid for 24h."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": email,
        "iat": now,
        "exp": now + timedelta(hours=_TOKEN_TTL_HOURS),
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, _secret(), algorithm=_ALGORITHM)


def verify_token(token: Optional[str]) -> Optional[str]:
    """Return the email (sub) for a valid token, or None if invalid/expired.

    Solo HS256, con emisor y audiencia propios, y el token tiene que traer vencimiento: uno sin `exp` valdría
    para siempre."""
    if not token:
        return None
    try:
        payload = jwt.decode(
            token,
            _secret(),
            algorithms=[_ALGORITHM],
            audience=_AUDIENCE,
            issuer=_ISSUER,
            options={"require": _REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError:
        return None
    sub = payload.get("sub")
    return sub if isinstance(sub, str) and sub else None
