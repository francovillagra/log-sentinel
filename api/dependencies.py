import os

from fastapi import Header, HTTPException, status


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
