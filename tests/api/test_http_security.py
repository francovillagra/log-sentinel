"""Cabeceras de seguridad, CORS, documentación, errores genéricos, tope de cuerpo e IP del cliente."""
import httpx
import pytest
from starlette.requests import Request

from api import security
from tests.api.conftest import INGEST_KEY, make_app

EXPECTED_HEADERS = {
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
}


def assert_secure(response):
    for name, value in EXPECTED_HEADERS.items():
        assert response.headers.get(name) == value, f"falta {name} en {response.status_code}"
    assert "max-age" in response.headers.get("strict-transport-security", "")


def client_for(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test")


async def test_security_headers_on_success_and_error_responses(nodb_client):
    responses = {
        200: await nodb_client.get("/health"),
        401: await nodb_client.post("/api/v1/ingest", json={"line": "x"}),
        404: await nodb_client.get("/no-such-route"),
        405: await nodb_client.delete("/health"),
        422: await nodb_client.post("/api/v1/auth/login", json={"email": "a@b.c"}),
    }
    for expected, response in responses.items():
        assert response.status_code == expected
        assert_secure(response)


async def test_validation_errors_do_not_echo_the_input(nodb_client):
    marker = "M" * 200
    response = await nodb_client.post("/api/v1/auth/login", json={"email": "a@b.c", "password": marker})
    assert response.status_code == 422
    assert marker not in response.text
    assert all(set(e) <= {"type", "loc", "msg"} for e in response.json()["detail"])


async def test_unhandled_errors_are_generic_and_still_carry_headers(monkeypatch):
    app = make_app(None)

    @app.get("/boom")
    async def boom():
        raise RuntimeError("detalle interno que no debe salir: clave=hunter2")

    async with client_for(app) as client:
        response = await client.get("/boom")
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "hunter2" not in response.text
    assert_secure(response)


async def test_api_docs_are_off_unless_debug(monkeypatch):
    async with client_for(make_app(None)) as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert (await client.get(path)).status_code == 404

    monkeypatch.setenv("DEBUG", "true")
    async with client_for(make_app(None)) as client:
        assert (await client.get("/openapi.json")).status_code == 200


async def test_cors_allows_only_configured_origins_without_credentials(nodb_client):
    ok = await nodb_client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert ok.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "access-control-allow-credentials" not in ok.headers
    assert "Retry-After" in ok.headers["access-control-expose-headers"]

    evil = await nodb_client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in evil.headers

    # Un error también lleva los encabezados CORS: sin ellos el dashboard no podría leer ni el 401 ni el 429.
    err = await nodb_client.get("/api/v1/alerts", headers={"Origin": "http://localhost:3000"})
    assert err.status_code == 401 and err.headers["access-control-allow-origin"] == "http://localhost:3000"


async def test_cors_preflight(nodb_client):
    base = {"Origin": "http://localhost:3000", "Access-Control-Request-Headers": "authorization,content-type"}
    allowed = await nodb_client.options("/api/v1/auth/login", headers={**base, "Access-Control-Request-Method": "POST"})
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "DELETE" not in allowed.headers["access-control-allow-methods"]

    denied_method = await nodb_client.options("/api/v1/alerts", headers={**base, "Access-Control-Request-Method": "DELETE"})
    assert denied_method.status_code == 400

    denied_origin = await nodb_client.options(
        "/api/v1/auth/login",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert denied_origin.status_code == 400


async def test_body_over_the_limit_is_a_413_with_headers(monkeypatch):
    monkeypatch.setenv("MAX_REQUEST_BYTES", "1000")
    async with client_for(make_app(None)) as client:
        declared = await client.post("/api/v1/ingest", content=b"x" * 5000,
                                     headers={"X-API-Key": INGEST_KEY, "Content-Type": "application/json"})
        assert declared.status_code == 413
        assert_secure(declared)

        async def chunks():  # sin Content-Length: llega por partes
            for _ in range(20):
                yield b"x" * 200

        chunked = await client.post("/api/v1/ingest", content=chunks(),
                                    headers={"X-API-Key": INGEST_KEY, "Content-Type": "application/json"})
        assert chunked.status_code == 413
        assert_secure(chunked)

        small = await client.post("/api/v1/ingest", json={"line": "x"}, headers={"X-API-Key": INGEST_KEY})
        assert small.status_code == 200


# ── IP del cliente ───────────────────────────────────────────────────────────────────────────────────────────────

def request_from(peer: str, forwarded: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers, "client": (peer, 5000)})


def test_forwarded_header_is_ignored_without_trusted_proxies(monkeypatch):
    monkeypatch.delenv("TRUSTED_PROXY_COUNT", raising=False)
    assert security.client_ip(request_from("10.0.0.1", "1.2.3.4")) == "10.0.0.1"


def test_with_one_trusted_proxy_the_rightmost_entry_wins(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    # El cliente puede escribir lo que quiera a la izquierda; lo que anotó el proxy propio queda a la derecha.
    assert security.client_ip(request_from("10.0.0.1", "6.6.6.6, 203.0.113.9")) == "203.0.113.9"
    assert security.client_ip(request_from("10.0.0.1")) == "10.0.0.1"
    assert security.client_ip(request_from("10.0.0.1", "not-an-ip")) == "10.0.0.1"


def test_two_trusted_proxies_take_the_second_from_the_right(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "2")
    assert security.client_ip(request_from("10.0.0.1", "6.6.6.6, 203.0.113.9, 10.1.1.1")) == "203.0.113.9"
    assert security.client_ip(request_from("10.0.0.1", "203.0.113.9")) == "10.0.0.1"  # menos saltos de los esperados


def test_ipv6_clients_are_grouped_by_their_64(monkeypatch):
    monkeypatch.delenv("TRUSTED_PROXY_COUNT", raising=False)
    a = security.rate_limit_key(request_from("2001:db8:abcd:12::1"))
    b = security.rate_limit_key(request_from("2001:db8:abcd:12:ffff:ffff:ffff:ffff"))
    c = security.rate_limit_key(request_from("2001:db8:abcd:13::1"))
    assert a == b != c
    assert security.rate_limit_key(request_from("192.0.2.1")) == "192.0.2.1"


# ── Registro de accesos ──────────────────────────────────────────────────────────────────────────────────────────

def test_session_tokens_are_not_written_to_the_access_log():
    import logging

    from api.main import RedactTokens

    record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
                               ("1.2.3.4:5", "GET", "/ws/alerts?token=eyJhbGciOi.secret.sig&x=1", "1.1", 200), None)
    assert RedactTokens().filter(record) is True
    line = record.getMessage()
    assert "eyJhbGciOi" not in line and "secret" not in line
    assert "/ws/alerts?token=<oculto>&x=1" in line


def test_a_real_uvicorn_server_never_logs_the_websocket_token(caplog):
    """Con un servidor de verdad: uvicorn registra la conexión WebSocket con la URL completa, token incluido."""
    import logging
    import socket
    import threading
    import time

    import uvicorn
    from websockets.sync.client import connect

    from api.services.auth_service import create_access_token

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(make_app(None), host="127.0.0.1", port=port, log_config=None, lifespan="off"))
    thread = threading.Thread(target=server.run, daemon=True)
    token = create_access_token("admin@example.com")
    with caplog.at_level(logging.INFO):
        thread.start()
        try:
            for _ in range(100):
                if server.started:
                    break
                time.sleep(0.05)
            assert server.started
            with connect(f"ws://127.0.0.1:{port}/ws/alerts?token={token}"):
                pass
            time.sleep(0.3)
        finally:
            server.should_exit = True
            thread.join(timeout=5)

    text = caplog.text
    assert "WebSocket /ws/alerts" in text  # sí se registró la conexión...
    assert token not in text and token.split(".")[1] not in text  # ...pero sin el token
    assert "token=<oculto>" in text
