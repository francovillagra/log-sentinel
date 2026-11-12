"""Servidor de la consola de la demo: el ejecutor de escenarios y las defensas contra otros sitios abiertos en el navegador."""
import http.client
import json
import socket
import threading
import time

import pytest

from api.main import build_engine
from demo.console import server


def engine_as_api():
    """Hace de API: procesa las líneas con el motor real y responde con el formato de POST /api/v1/ingest."""
    engine = build_engine()
    calls = []

    def send(lines):
        calls.append(list(lines))
        alerts = []
        for line in lines:
            _event, found = engine.process_line(line)
            alerts += [{"rule_id": a.rule_id, "severity": a.severity.value, "src_ip": a.src_ip, "title": a.title,
                        "evidence": a.evidence} for a in found]
        return {"processed": len(lines), "alerts_fired": len(alerts), "alerts": alerts}

    send.calls = calls
    return send


def runner_with(send, sleeps=None):
    return server.Runner(send, sleep=(sleeps.append if sleeps is not None else (lambda _s: None)))


# --- el ejecutor ---------------------------------------------------------------------------------------------------------

def test_the_campaign_records_one_successful_event_per_stage():
    sleeps = []
    runner = runner_with(engine_as_api(), sleeps)
    assert runner.start("campaign", wait=True) == "started"
    events, running = runner.events_since(0)
    assert running is False
    assert [e["step"] for e in events] == [1, 2, 3, 4, 5] and all(e["steps"] == 5 for e in events)
    assert [e["n"] for e in events] == [1, 2, 3, 4, 5]
    assert all(e["ok"] and e["error"] is None for e in events)
    assert [e["expect"] for e in events] == [["suspicious_ua"], ["brute_force"], ["sqli"], ["path_traversal"], ["rate_anomaly"]]
    assert sleeps == [2.5, 2.5, 2.5, 2.5], "hay pausa entre etapas, no después de la última"
    assert events[1]["alerts"][0]["label"] == "Prueba de contraseñas (fuerza bruta)"
    assert events[1]["alerts"][0]["severity_label"] == "alta"


def test_normal_traffic_is_ok_only_when_nothing_fires():
    runner = runner_with(engine_as_api())
    runner.start("normal", wait=True)
    (event,) = runner.events_since(0)[0]
    assert event["ok"] and event["alerts"] == [] and event["expect"] == [] and event["sent"] == 24

    noisy = runner_with(lambda lines: {"alerts": [{"rule_id": "sqli", "severity": "HIGH", "src_ip": "x", "evidence": "e"}]})
    noisy.start("normal", wait=True)
    (false_alarm,) = noisy.events_since(0)[0]
    assert false_alarm["ok"] is False and false_alarm["alerts"], "un aviso donde no correspondía es una falla, no un éxito"


def test_an_attack_that_the_engine_misses_is_reported_as_not_ok():
    runner = runner_with(lambda lines: {"alerts": []})
    runner.start("sqli", wait=True)
    (event,) = runner.events_since(0)[0]
    assert event["ok"] is False and event["error"] is None


def test_if_the_api_is_down_the_sequence_stops_at_the_first_stage():
    sent = []

    def down(lines):
        sent.append(lines)
        raise server.IngestError("No se pudo hablar con la API.")

    runner = runner_with(down)
    runner.start("campaign", wait=True)
    events, running = runner.events_since(0)
    assert len(events) == 1 and len(sent) == 1
    assert events[0]["error"] == "No se pudo hablar con la API." and events[0]["ok"] is False
    assert running is False


def test_an_unexpected_error_does_not_leave_the_console_stuck_as_busy():
    def broken(lines):
        raise RuntimeError("falla interna")

    runner = runner_with(broken)
    runner.start("passwords", wait=True)
    events, running = runner.events_since(0)
    assert running is False and "inesperado" in events[0]["error"]
    assert "falla interna" not in json.dumps(events), "el detalle interno queda en el registro, no en la página"
    assert runner.start("passwords", wait=True) == "started"


def test_only_one_test_runs_at_a_time_and_unknown_ids_are_refused():
    release = threading.Event()
    inside = threading.Event()

    def slow(lines):
        inside.set()
        release.wait(5)
        return {"alerts": []}

    runner = runner_with(slow)
    assert runner.start("passwords") == "started"
    assert inside.wait(5)
    assert runner.start("sqli") == "busy"
    assert runner.events_since(0) == ([], True)
    release.set()
    deadline = time.time() + 5
    while runner.events_since(0)[1] and time.time() < deadline:
        time.sleep(0.01)
    assert runner.start("sqli", wait=True) == "started"
    assert runner.start("no-existe") == "unknown"
    assert runner.start("../../etc/passwd") == "unknown"


def test_events_since_returns_only_the_newer_ones():
    runner = runner_with(engine_as_api())
    runner.start("passwords", wait=True)
    runner.start("sqli", wait=True)
    assert [e["n"] for e in runner.events_since(0)[0]] == [1, 2]
    assert [e["n"] for e in runner.events_since(1)[0]] == [2]
    assert runner.events_since(2)[0] == []


def test_the_log_keeps_only_the_latest_events():
    runner = runner_with(lambda lines: {"alerts": []})
    for _ in range(server.MAX_EVENTS + 20):
        runner.start("sqli", wait=True)
    events, _ = runner.events_since(0)
    assert len(events) == server.MAX_EVENTS and events[-1]["n"] == server.MAX_EVENTS + 20


# --- el envío real a la API (con el pedido interceptado) --------------------------------------------------------------------

def test_the_api_sender_posts_in_chunks_with_the_ingest_key_and_never_leaks_it(tmp_path, monkeypatch):
    (tmp_path / "ingest_api_key").write_text("clave-de-prueba-que-no-debe-salir\n")
    seen = []

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, *_):
            return json.dumps(self._payload).encode()

    def fake_urlopen(request, timeout=None):
        body = json.loads(request.data)
        seen.append((request.full_url, request.get_header("X-api-key"), len(body["lines"])))
        return FakeResponse({"processed": len(body["lines"]), "alerts_fired": 1, "alerts": [{"rule_id": "x"}]})

    monkeypatch.setattr(server.urllib.request, "urlopen", fake_urlopen)
    sender = server.ApiSender(server.Config(api_url="http://api:8000", secrets_dir=tmp_path))
    result = sender([f"l{i}" for i in range(1200)])
    assert [s[2] for s in seen] == [500, 500, 200]
    assert all(s[0] == "http://api:8000/api/v1/ingest" and s[1] == "clave-de-prueba-que-no-debe-salir" for s in seen)
    assert result["processed"] == 1200 and result["alerts_fired"] == 3 and len(result["alerts"]) == 3


def test_the_api_sender_explains_errors_without_exposing_the_key(tmp_path, monkeypatch):
    sender = server.ApiSender(server.Config(secrets_dir=tmp_path))
    with pytest.raises(server.IngestError, match="todavía no están listas"):
        sender(["x"])

    (tmp_path / "ingest_api_key").write_text("secreto-que-no-debe-aparecer")
    import urllib.error

    def refused(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, 401, "no", {}, None)

    monkeypatch.setattr(server.urllib.request, "urlopen", refused)
    with pytest.raises(server.IngestError) as exc:
        sender(["x"])
    assert "secreto-que-no-debe-aparecer" not in str(exc.value) and "down -v" in str(exc.value)

    def unreachable(request, timeout=None):
        raise urllib.error.URLError("conexión rechazada")

    monkeypatch.setattr(server.urllib.request, "urlopen", unreachable)
    with pytest.raises(server.IngestError, match="No se pudo hablar con la API"):
        sender(["x"])


# --- el servidor HTTP -------------------------------------------------------------------------------------------------------

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def console(tmp_path):
    port = free_port()
    (tmp_path / "admin_email").write_text("demo@log-sentinel.test\n")
    (tmp_path / "admin_password").write_text("faro-cobre-nube-47\n")
    config = server.Config(public_port=port, secrets_dir=tmp_path, listen_host="127.0.0.1", listen_port=port)
    runner = runner_with(engine_as_api())
    httpd = server.create_server(config, runner, ready=lambda: True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield port, runner, tmp_path
    httpd.shutdown()
    httpd.server_close()


def call(port, method, path, host=None, origin=None, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    sent = {"Host": host or f"localhost:{port}", **(headers or {})}
    if origin:
        sent["Origin"] = origin
    conn.request(method, path, body=body, headers=sent)
    response = conn.getresponse()
    data = response.read()
    result = (response.status, {k.lower(): v for k, v in response.getheaders()}, data)
    conn.close()
    return result


def test_the_page_and_its_assets_are_served_with_security_headers_and_no_server_banner(console):
    port, _, _ = console
    for path, ctype in (("/", "text/html"), ("/app.js", "text/javascript"), ("/style.css", "text/css")):
        status, headers, body = call(port, "GET", path)
        assert status == 200 and headers["content-type"].startswith(ctype) and body
        assert "script-src 'self'" in headers["content-security-policy"]
        assert "'unsafe-inline'" not in headers["content-security-policy"]
        assert headers["x-content-type-options"] == "nosniff" and headers["x-frame-options"] == "DENY"
        assert headers["cache-control"] == "no-store" and "server" not in headers


def test_a_request_with_a_foreign_host_is_refused_so_dns_rebinding_does_not_work(console):
    port, _, _ = console
    for path in ("/", "/api/state", "/api/events"):
        assert call(port, "GET", path, host=f"atacante.example:{port}")[0] == 421
    assert call(port, "GET", "/api/state", host="localhost")[0] == 421       # sin el puerto no es el de la consola
    assert call(port, "GET", "/api/state", host=f"127.0.0.1:{port}")[0] == 200
    assert call(port, "GET", "/healthz", host="cualquiera")[0] == 200         # docker lo consulta desde adentro


def test_posts_need_the_consoles_own_origin(console):
    port, runner, _ = console
    own = f"http://localhost:{port}"
    assert call(port, "POST", "/api/run/sqli")[0] == 403                                       # sin Origin
    assert call(port, "POST", "/api/run/sqli", origin="https://sitio-ajeno.example")[0] == 403  # otra página
    assert call(port, "POST", "/api/run/sqli", origin="null")[0] == 403
    assert call(port, "POST", "/api/run/sqli", origin=own, host="otro.example")[0] == 421
    assert runner.events_since(0)[0] == [], "ninguno de los rechazados ejecutó algo"
    status, _, body = call(port, "POST", "/api/run/sqli", origin=own)
    assert status == 202 and json.loads(body) == {"result": "started"}


def test_unknown_routes_and_oversized_bodies_are_refused(console):
    port, _, _ = console
    own = f"http://localhost:{port}"
    assert call(port, "POST", "/api/run/no-existe", origin=own)[0] == 404
    assert call(port, "POST", "/api/run/../x", origin=own)[0] == 404
    assert call(port, "POST", "/api/run/SQLI", origin=own)[0] == 404
    assert call(port, "POST", "/otra-cosa", origin=own)[0] == 404
    assert call(port, "GET", "/api/run/sqli")[0] == 404
    assert call(port, "POST", "/api/run/sqli", origin=own, headers={"Content-Length": "5000"})[0] == 413
    assert call(port, "DELETE", "/")[0] in (404, 405, 501)


def test_a_test_started_over_http_shows_up_in_the_events(console):
    port, runner, _ = console
    call(port, "POST", "/api/run/passwords", origin=f"http://127.0.0.1:{port}", host=f"127.0.0.1:{port}")
    deadline = time.time() + 5
    while time.time() < deadline:
        _, _, body = call(port, "GET", "/api/events?since=0")
        payload = json.loads(body)
        if payload["events"] and not payload["running"]:
            break
        time.sleep(0.02)
    (event,) = payload["events"]
    assert event["ok"] and event["alerts"][0]["rule_id"] == "brute_force" and payload["running"] is False
    assert json.loads(call(port, "GET", "/api/events?since=1")[2])["events"] == []
    assert json.loads(call(port, "GET", "/api/events?since=basura")[2])["events"][0]["n"] == 1


def test_state_lists_the_scenarios_and_the_login_only_when_the_credentials_exist(console):
    port, _, directory = console
    state = json.loads(call(port, "GET", "/api/state")[2])
    assert [s["id"] for s in state["scenarios"]] == ["normal", "passwords", "sqli", "campaign", "xss", "files", "tool", "flood"]
    assert state["api_ready"] is True and state["panel_url"].startswith("http://localhost:")
    assert state["login"] == {"email": "demo@log-sentinel.test", "password": "faro-cobre-nube-47"}
    (directory / "admin_password").unlink()
    assert json.loads(call(port, "GET", "/api/state")[2])["login"] is None
