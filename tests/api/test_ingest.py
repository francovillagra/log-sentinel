"""POST /api/v1/ingest: autenticación por clave, topes de tamaño y guardado acotado."""
import asyncio
import json

import pytest

from api.services import alerts_db
from engine.models import Alert, Severity
from tests.api.conftest import INGEST_KEY, bearer
from tests.engine.helpers import nginx_line

KEY = {"X-API-Key": INGEST_KEY}
SQLI = nginx_line("/p?id=1%20UNION%20SELECT%201,2--%20-", ip="198.51.100.7")


async def test_ingest_requires_the_api_key(nodb_client):
    assert (await nodb_client.post("/api/v1/ingest", json={"line": SQLI})).status_code == 401
    wrong = await nodb_client.post("/api/v1/ingest", json={"line": SQLI}, headers={"X-API-Key": "x" * 40})
    assert wrong.status_code == 401
    assert (await nodb_client.post("/api/v1/ingest", json={"line": SQLI}, headers={"X-API-Key": ""})).status_code == 401


async def test_a_key_with_non_ascii_bytes_is_a_401_not_a_500(nodb_client):
    # compare_digest sobre str con caracteres no ASCII levanta TypeError: por eso se comparan bytes.
    response = await nodb_client.post(
        "/api/v1/ingest", json={"line": SQLI}, headers={"X-API-Key": "clave-ñ-no-válida".encode("latin-1")}
    )
    assert response.status_code == 401


async def test_ingest_with_the_key_detects_an_attack(nodb_client):
    response = await nodb_client.post("/api/v1/ingest", json={"line": SQLI}, headers=KEY)
    assert response.status_code == 200
    body = response.json()
    assert body["processed"] == 1 and body["alerts_fired"] >= 1
    assert any(a["src_ip"] == "198.51.100.7" for a in body["alerts"])


async def test_ingest_needs_line_or_lines(nodb_client):
    assert (await nodb_client.post("/api/v1/ingest", json={}, headers=KEY)).status_code == 422


async def test_the_number_of_lines_per_request_is_capped(nodb_client):
    ok = await nodb_client.post("/api/v1/ingest", json={"lines": ["x"] * 1000}, headers=KEY)
    assert ok.status_code == 200 and ok.json()["processed"] == 1000

    marker = "MARCADOR-QUE-NO-DEBE-VOLVER"
    too_many = await nodb_client.post("/api/v1/ingest", json={"lines": [marker] * 1001}, headers=KEY)
    assert too_many.status_code == 422
    assert marker not in too_many.text  # la validación no devuelve lo que recibió
    assert "input" not in json.dumps(too_many.json())


async def test_history_requires_a_bearer_token(nodb_client):
    assert (await nodb_client.get("/api/v1/alerts")).status_code == 401
    assert (await nodb_client.get("/api/v1/alerts", headers={"Authorization": "Basic abc"})).status_code == 401
    assert (await nodb_client.get("/api/v1/alerts", headers={"Authorization": "Bearer nope"})).status_code == 401
    # La clave de ingesta no sirve como sesión del dashboard.
    assert (await nodb_client.get("/api/v1/alerts", headers=KEY)).status_code == 401


@pytest.mark.db
async def test_history_returns_what_was_ingested_and_validates_limit(client):
    sent = await client.post("/api/v1/ingest", json={"line": SQLI}, headers=KEY)
    assert sent.json()["alerts_fired"] >= 1
    await asyncio.gather(*alerts_db._pending_saves)  # el guardado va en segundo plano

    history = await client.get("/api/v1/alerts", headers=bearer())
    assert history.status_code == 200
    assert any(a["src_ip"] == "198.51.100.7" for a in history.json())

    assert (await client.get("/api/v1/alerts?limit=0", headers=bearer())).status_code == 422
    assert (await client.get("/api/v1/alerts?limit=501", headers=bearer())).status_code == 422


def _alert() -> Alert:
    return Alert(ts=__import__("datetime").datetime(2026, 1, 1), src_ip="203.0.113.9", rule_id="R", severity=Severity.HIGH,
                 title="t", description="d", evidence="e", raw_event="r")


async def test_background_saves_are_bounded_and_referenced(monkeypatch):
    release = asyncio.Event()

    async def slow_save(pool, alert):
        await release.wait()

    monkeypatch.setattr(alerts_db, "save_alert", slow_save)
    monkeypatch.setattr(alerts_db, "dropped_saves", 0)
    assert not alerts_db._pending_saves

    results = [alerts_db.schedule_save(None, _alert()) for _ in range(alerts_db.MAX_PENDING_SAVES + 25)]

    assert results.count(True) == alerts_db.MAX_PENDING_SAVES  # entran hasta el tope
    assert results.count(False) == 25                           # el resto se descarta y se cuenta
    assert alerts_db.dropped_saves == 25
    assert len(alerts_db._pending_saves) == alerts_db.MAX_PENDING_SAVES  # con referencia fuerte a cada tarea

    release.set()
    await asyncio.gather(*list(alerts_db._pending_saves))
    await asyncio.sleep(0)
    assert not alerts_db._pending_saves  # al terminar se liberan
    assert alerts_db.schedule_save(None, _alert()) is True  # y vuelve a haber lugar
    await asyncio.gather(*list(alerts_db._pending_saves))
