import asyncio

from fastapi import WebSocket

from api.config import max_ws_connections

# Un cliente que no lee (red caída, pestaña congelada) no puede frenar la entrega al resto.
SEND_TIMEOUT_SECONDS = 5.0


class ConnectionManager:
    """WebSocket connection registry with thread-safe broadcast."""

    def __init__(self) -> None:
        self.active_connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> bool:
        """Registra la conexión. Devuelve False (sin aceptarla) si ya se llegó al tope de conexiones."""
        async with self._lock:
            if len(self.active_connections) >= max_ws_connections():
                return False
            self.active_connections.add(ws)
        await ws.accept()
        return True

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self.active_connections.discard(ws)

    async def broadcast(self, message: str) -> None:
        """Send message to all clients at once; drop the ones that fail or take too long."""
        async with self._lock:
            snapshot = list(self.active_connections)

        async def send(ws: WebSocket) -> bool:
            try:
                await asyncio.wait_for(ws.send_text(message), timeout=SEND_TIMEOUT_SECONDS)
                return True
            except Exception:  # noqa: BLE001 — una conexión caída o lenta se descarta
                return False

        results = await asyncio.gather(*(send(ws) for ws in snapshot))
        dead = {ws for ws, ok in zip(snapshot, results) if not ok}
        if dead:
            async with self._lock:
                self.active_connections -= dead


broadcaster = ConnectionManager()
