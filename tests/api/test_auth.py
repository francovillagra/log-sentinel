"""Login: límites de intentos, bcrypt fuera del bucle de eventos, mismo trabajo para usuarios inexistentes y tokens estrictos."""
import asyncio
import time
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import pytest

from api.services import auth_service

from .conftest import ADMIN_EMAIL, ADMIN_PASSWORD

pytestmark = pytest.mark.db

LOGIN = "/api/v1/auth/login"


async def _login(client, email=ADMIN_EMAIL, password=ADMIN_PASSWORD, **kw):
    return await client.post(LOGIN, json={"email": email, "password": password}, **kw)


async def test_login_returns_a_token_with_strict_claims(client, admin):
    res = await _login(client)

    assert res.status_code == 200
    token = res.json()["access_token"]
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["sub"] == ADMIN_EMAIL
    assert claims["iss"] == "log-sentinel" and claims["aud"] == "log-sentinel-dashboard"
    assert {"exp", "iat", "jti"} <= set(claims)
    assert auth_service.verify_token(token) == ADMIN_EMAIL


async def test_the_email_is_case_insensitive(client, admin):
    assert (await _login(client, email=ADMIN_EMAIL.upper())).status_code == 200


async def test_wrong_password_and_unknown_email_look_the_same(client, admin):
    wrong = await _login(client, password="nope-nope-nope")
    unknown = await _login(client, email="nadie@example.com")

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


async def test_an_unknown_email_costs_the_same_bcrypt_work(client, admin, monkeypatch):
    """Si el correo no existe igual se corre bcrypt: el tiempo de respuesta no delata qué correos están registrados."""
    calls = []
    real = bcrypt.checkpw
    monkeypatch.setattr(auth_service.bcrypt, "checkpw", lambda *a: (calls.append(a[1]), real(*a))[1])

    await _login(client, password="nope-nope-nope")
    await _login(client, email="nadie@example.com", password="nope-nope-nope")

    assert len(calls) == 2
    # El hash de relleno es un hash bcrypt de verdad, con el mismo costo que los reales (uno mal formado falla al
    # instante y el tiempo de respuesta delataría que el correo no existe).
    real_hash, stand_in = calls
    assert real_hash.split(b"$")[2] == stand_in.split(b"$")[2]
    assert real(b"password-for-timing-equalization", stand_in) is True


async def test_the_stand_in_hash_never_authenticates(client, admin):
    """Un usuario inexistente no entra aunque se conozca la contraseña del hash de relleno."""
    res = await _login(client, email="nadie@example.com", password="password-for-timing-equalization")
    assert res.status_code == 401


async def test_eight_failures_lock_that_address_and_account(client, admin):
    for _ in range(8):
        assert (await _login(client, password="nope-nope-nope")).status_code == 401

    blocked = await _login(client)  # ni siquiera la contraseña correcta pasa mientras dura el bloqueo
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0


async def test_the_lock_is_per_account_not_per_address(client, admin):
    for _ in range(8):
        await _login(client, password="nope-nope-nope")

    other = await _login(client, email="otra@example.com", password="nope-nope-nope")

    assert other.status_code == 401  # otra cuenta desde la misma dirección todavía puede intentar


async def test_a_successful_login_gives_the_attempts_back(client, admin):
    for _ in range(7):
        await _login(client, password="nope-nope-nope")
    assert (await _login(client)).status_code == 200
    for _ in range(7):
        assert (await _login(client, password="nope-nope-nope")).status_code == 401


async def test_parallel_guesses_do_not_get_extra_attempts(client, admin, monkeypatch):
    """El cupo se reserva antes de calcular el hash: 40 pedidos en paralelo no son 40 intentos permitidos."""
    calls = []
    real = bcrypt.checkpw
    monkeypatch.setattr(auth_service.bcrypt, "checkpw", lambda *a: (calls.append(1), real(*a))[1])

    results = await asyncio.gather(*[_login(client, password="nope-nope-nope") for _ in range(40)])

    codes = [r.status_code for r in results]
    assert codes.count(401) == 8 and codes.count(429) == 32
    assert len(calls) == 8


async def test_login_inputs_have_a_size_limit_and_are_not_echoed(client, admin):
    res = await _login(client, password="x" * 129)

    assert res.status_code == 422
    assert "x" * 20 not in res.text


async def test_bcrypt_does_not_block_the_event_loop(client, admin, monkeypatch):
    """Con bcrypt en el hilo del servidor, cada hash (~250 ms con costo 12) congelaba todo lo demás."""
    monkeypatch.setenv("BCRYPT_ROUNDS", "12")
    from api.services.auth_service import hash_password

    async with client._transport.app.state.db_pool.acquire() as conn:
        await conn.execute("UPDATE users SET password_hash = $1", hash_password(ADMIN_PASSWORD))

    gaps, stop = [], False

    async def ticker():
        last = time.perf_counter()
        while not stop:
            await asyncio.sleep(0.005)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    task = asyncio.create_task(ticker())
    await asyncio.sleep(0.05)
    gaps.clear()
    results = await asyncio.gather(*[_login(client) for _ in range(2)])
    stop = True
    await task

    assert all(r.status_code == 200 for r in results)
    assert max(gaps) < 0.1, f"el bucle de eventos estuvo {max(gaps) * 1000:.0f} ms sin responder"


async def test_too_much_password_work_answers_503_instead_of_queueing(client, admin, monkeypatch):
    monkeypatch.setenv("BCRYPT_MAX_PENDING", "1")
    monkeypatch.setattr(auth_service, "_executor", None)

    results = await asyncio.gather(*[_login(client, email=f"u{i}@example.com", password="nope-nope-nope") for i in range(4)])

    codes = sorted(r.status_code for r in results)
    assert 503 in codes and codes.count(401) >= 1
    assert all(r.headers.get("Retry-After") for r in results if r.status_code == 503)


# ── tokens ──────────────────────────────────────────────────────────────────────────────────────────────────────

SECRET = None


def _claims(**over):
    now = datetime.now(timezone.utc)
    claims = {"sub": ADMIN_EMAIL, "iat": now, "exp": now + timedelta(hours=1), "iss": "log-sentinel",
              "aud": "log-sentinel-dashboard", "jti": "x"}
    claims.update(over)
    return {k: v for k, v in claims.items() if v is not None}


def _token(claims, algorithm="HS256", key=None):
    import os

    return jwt.encode(claims, key or os.environ["JWT_SECRET"], algorithm=algorithm)


def test_a_well_formed_token_is_accepted():
    assert auth_service.verify_token(_token(_claims())) == ADMIN_EMAIL


@pytest.mark.parametrize("claims", [
    _claims(exp=None),                                              # sin vencimiento valdría para siempre
    _claims(iat=None),
    _claims(sub=None),
    _claims(iss="otro"),
    _claims(aud="otra-app"),
    _claims(exp=datetime.now(timezone.utc) - timedelta(seconds=5)),  # vencido
], ids=["sin-exp", "sin-iat", "sin-sub", "emisor-ajeno", "audiencia-ajena", "vencido"])
def test_tokens_that_do_not_meet_the_rules_are_refused(claims):
    assert auth_service.verify_token(_token(claims)) is None


def test_other_algorithms_and_unsigned_tokens_are_refused():
    import os

    # Firmados con el secreto correcto: lo único que cambia es el algoritmo.
    for algorithm in ("HS384", "HS512"):
        assert auth_service.verify_token(_token(_claims(), algorithm=algorithm, key=os.environ["JWT_SECRET"])) is None
    unsigned = jwt.encode(_claims(), key=None, algorithm="none")
    assert auth_service.verify_token(unsigned) is None
    assert auth_service.verify_token(_token(_claims(), key="otra-clave-" * 5)) is None
    assert auth_service.verify_token("no-es-un-token") is None
    assert auth_service.verify_token(None) is None
