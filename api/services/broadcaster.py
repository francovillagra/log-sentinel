import asyncio

from fastapi import WebSocket


class ConnectionManager:
    """WebSocket connection registry with thread-safe broadcast."""

    def __init__(self) -> None:
        self.active_connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self.active_connections.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self.active_connections.discard(ws)

    async def broadcast(self, message: str) -> None:
        """Send message to all clients; silently drop dead connections."""
        async with self._lock:
            snapshot = set(self.active_connections)
        dead: set[WebSocket] = set()
        for ws in snapshot:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        if dead:
            async with self._lock:
                self.active_connections -= dead


broadcaster = ConnectionManager()
