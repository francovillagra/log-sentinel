from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.services.broadcaster import broadcaster

router = APIRouter()


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    """
    Stream real-time alerts to the client.
    Alerts are pushed by the broadcast_loop background task, not by this handler.
    The handler only waits to detect disconnection.
    """
    await broadcaster.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        await broadcaster.disconnect(websocket)
