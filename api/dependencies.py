import hmac
import os
from typing import Optional

from fastapi import Header, HTTPException, status

from api.services.auth_service import verify_token


async def verify_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Reject requests whose X-API-Key header doesn't match INGEST_API_KEY."""
    expected = os.environ.get("INGEST_API_KEY", "")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="INGEST_API_KEY is not configured on the server",
        )
    # Comparación en tiempo constante: con `!=` el tiempo de respuesta delata cuántos caracteres iniciales acertó.
    if not x_api_key or not hmac.compare_digest(x_api_key.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )


async def require_bearer_token(authorization: Optional[str] = Header(default=None)) -> str:
    """Validate an `Authorization: Bearer <jwt>` header; return the email (sub)."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
        )
    email = verify_token(token)
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    return email
