import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt

_ALGORITHM = "HS256"
_TOKEN_TTL_HOURS = 24


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt (includes a generated salt)."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time compare a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


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
    }
    return jwt.encode(payload, _secret(), algorithm=_ALGORITHM)


def verify_token(token: Optional[str]) -> Optional[str]:
    """Return the email (sub) for a valid token, or None if invalid/expired."""
    if not token:
        return None
    try:
        payload = jwt.decode(token, _secret(), algorithms=[_ALGORITHM])
    except jwt.PyJWTError:
        return None
    return payload.get("sub")
