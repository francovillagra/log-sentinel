from fastapi import APIRouter, Depends, Query, Request

from api.dependencies import require_bearer_token
from api.services.alerts_db import get_recent_alerts

router = APIRouter(prefix="/api/v1")


@router.get("/alerts")
async def alerts_history(
    request: Request,
    limit: int = Query(200, ge=1, le=500),
    _email: str = Depends(require_bearer_token),
) -> list[dict]:
    """Return persisted alerts (newest first). Requires a valid Bearer JWT."""
    pool = request.app.state.db_pool
    return await get_recent_alerts(pool, limit)
