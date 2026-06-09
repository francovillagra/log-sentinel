from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.services.auth_service import verify_token
from api.services.broadcaster import broadcaster

router = APIRouter()


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    """
    Stream real-time alerts to the client.

    The client must authenticate by passing a valid JWT as the `token` query
    param (?token=<jwt>). Alerts are pushed by the broadcast_loop background
    task, not by this handler — the handler only waits to detect disconnection.
    """
    token = websocket.query_params.get("token")
    email = verify_token(token)
    if email is None:
        await websocket.close(code=4001)
        return

    await broadcaster.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        await broadcaster.disconnect(websocket)
