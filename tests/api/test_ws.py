"""WebSocket de alertas: token, origen permitido, tope de conexiones y clientes lentos."""
import asyncio
import time

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from api.services import broadcaster as broadcaster_module
from api.services.broadcaster import ConnectionManager, broadcaster
from tests.api.conftest import ADMIN_EMAIL, make_app


@pytest.fixture(autouse=True)
def _clean_broadcaster():
    broadcaster.active_connections.clear()
    broadcaster._lock = asyncio.Lock()
    yield
    broadcaster.active_connections.clear()


def token() -> str:
    from api.services.auth_service import create_access_token

    return create_access_token(ADMIN_EMAIL)


def closes_with(client: TestClient, url: str, **kwargs) -> int:
    with pytest.raises(WebSocketDisconnect) as info:
        with client.websocket_connect(url, **kwargs):
            pass
    return info.value.code


def test_connection_without_or_with_a_bad_token_is_refused():
    with TestClient(make_app(None)) as client:
        assert closes_with(client, "/ws/alerts") == 4001
        assert closes_with(client, "/ws/alerts?token=basura") == 4001
        assert closes_with(client, "/ws/alerts?token=") == 4001


def test_a_valid_token_connects_and_receives_broadcasts():
    with TestClient(make_app(None)) as client:
        with client.websocket_connect(f"/ws/alerts?token={token()}") as ws:
            client.portal.call(broadcaster.broadcast, '{"rule_id": "X"}')
            assert ws.receive_text() == '{"rule_id": "X"}'


def test_a_browser_from_another_origin_is_refused_even_with_a_valid_token():
    with TestClient(make_app(None)) as client:
        url = f"/ws/alerts?token={token()}"
        assert closes_with(client, url, headers={"Origin": "https://evil.example"}) == 4403
        with client.websocket_connect(url, headers={"Origin": "http://localhost:3000"}):
            pass  # el origen del dashboard sí; y sin Origin (scripts) también, ver el test anterior


def test_connections_are_capped(monkeypatch):
    monkeypatch.setenv("MAX_WS_CONNECTIONS", "1")
    with TestClient(make_app(None)) as client:
        url = f"/ws/alerts?token={token()}"
        with client.websocket_connect(url):
            assert closes_with(client, url) == 4429
        # al liberarse el lugar, vuelve a poder conectarse
        time.sleep(0.2)
        with client.websocket_connect(url):
            pass


class FakeSocket:
    def __init__(self, delay: float | None = None) -> None:
        self.delay, self.received, self.accepted = delay, [], False

    async def accept(self) -> None:
        self.accepted = True

    async def send_text(self, message: str) -> None:
        if self.delay is not None:
            await asyncio.sleep(self.delay)
        self.received.append(message)


async def test_a_slow_client_does_not_hold_back_the_others(monkeypatch):
    monkeypatch.setattr(broadcaster_module, "SEND_TIMEOUT_SECONDS", 0.2)
    manager = ConnectionManager()
    slow, fast_1, fast_2 = FakeSocket(delay=30), FakeSocket(), FakeSocket()
    for ws in (slow, fast_1, fast_2):
        assert await manager.connect(ws)

    started = time.monotonic()
    await manager.broadcast("hola")
    elapsed = time.monotonic() - started

    assert elapsed < 2  # antes se esperaba a cada cliente en fila
    assert fast_1.received == fast_2.received == ["hola"]
    assert slow not in manager.active_connections and len(manager.active_connections) == 2


async def test_the_cap_applies_before_accepting(monkeypatch):
    monkeypatch.setenv("MAX_WS_CONNECTIONS", "2")
    manager = ConnectionManager()
    sockets = [FakeSocket() for _ in range(3)]
    assert [await manager.connect(ws) for ws in sockets] == [True, True, False]
    assert sockets[2].accepted is False
