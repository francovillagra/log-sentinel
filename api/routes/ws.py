from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.config import allowed_origins
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

    Un navegador que abre el WebSocket desde otro sitio manda su `Origin` (CORS no se aplica a los WebSocket):
    si viene y no es uno de los permitidos, se rechaza. Los clientes sin `Origin` (scripts) siguen necesitando
    el token.
    """
    origin = websocket.headers.get("origin")
    if origin is not None and origin.rstrip("/") not in allowed_origins():
        await websocket.close(code=4403)
        return

    token = websocket.query_params.get("token")
    email = verify_token(token)
    if email is None:
        await websocket.close(code=4001)
        return

    if not await broadcaster.connect(websocket):
        await websocket.close(code=4429)  # demasiadas conexiones
        return
    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        await broadcaster.disconnect(websocket)
