import os

from fastapi import Header, HTTPException, status

from api.services.auth_service import verify_token


async def verify_api_key(x_api_key: str = Header(...)) -> None:
    """Reject requests whose X-API-Key header doesn't match INGEST_API_KEY."""
    expected = os.environ.get("INGEST_API_KEY", "")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="INGEST_API_KEY is not configured on the server",
        )
    if x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )


async def require_bearer_token(authorization: str = Header(...)) -> str:
    """Validate an `Authorization: Bearer <jwt>` header; return the email (sub)."""
    scheme, _, token = authorization.partition(" ")
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
