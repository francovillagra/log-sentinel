"""Consola de la demo: cada botón dispara la regla que promete (contra el motor real) y el tráfico normal no dispara nada.

Si alguien toca un umbral o un patrón en engine/rules.py y un botón de la demo deja de mostrar su aviso, estas pruebas lo
dicen antes de que lo vea un cliente.
"""
import ipaddress
import random
from datetime import datetime, timezone

import pytest

from api.main import build_engine
from demo.console import scenarios as sc

DOCUMENTATION_BLOCKS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
SEEDS = range(25)  # cada tipo de ataque tiene varias variantes: con varias semillas se recorren todas


def _fired(engine, step):
    """Reglas que saltaron al procesar las líneas del paso, y los eventos que no se pudieron leer."""
    rules, unparsed = [], 0
    for line in step.lines(datetime.now(timezone.utc)):
        event, alerts = engine.process_line(line)
        unparsed += event is None
        rules += [a.rule_id for a in alerts]
    return rules, unparsed


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("scenario", sc.SCENARIOS, ids=lambda s: s.id)
def test_each_button_fires_what_it_promises_and_nothing_else_is_missed(scenario, seed):
    rng = random.Random(seed)
    engine = build_engine()
    for step in scenario.plan(sc.Addresses(rng), rng):
        rules, unparsed = _fired(engine, step)
        assert unparsed == 0, "una línea que el motor no entiende no puede disparar nada"
        if step.expect:
            assert set(step.expect) <= set(rules), f"{scenario.id}: esperaba {step.expect}, saltó {rules}"
        else:
            assert rules == [], f"{scenario.id}: el tráfico normal disparó {rules}"


@pytest.mark.parametrize("scenario_id", ["passwords", "flood", "sqli", "tool"])
def test_pressing_the_same_button_again_shows_a_new_alert(scenario_id):
    # Los detectores con estado avisan una vez por dirección y ventana: por eso cada clic usa un atacante distinto.
    rng = random.Random(7)
    addresses, engine = sc.Addresses(rng), build_engine()
    scenario = sc.BY_ID[scenario_id]
    seen = set()
    for _ in range(15):
        (step,) = scenario.plan(addresses, rng)
        rules, _ = _fired(engine, step)
        assert set(step.expect) <= set(rules)
        assert step.ip not in seen
        seen.add(step.ip)


def test_the_campaign_fires_one_rule_per_stage_from_the_same_attacker():
    rng = random.Random(3)
    engine = build_engine()
    steps = sc.BY_ID["campaign"].plan(sc.Addresses(rng), rng)
    assert [s.expect for s in steps] == [("suspicious_ua",), ("brute_force",), ("sqli",), ("path_traversal",), ("rate_anomaly",)]
    assert len({s.ip for s in steps}) == 1
    for step in steps:
        rules, _ = _fired(engine, step)
        assert set(step.expect) <= set(rules)


def test_every_address_in_the_practice_traffic_is_reserved_for_documentation():
    rng = random.Random(11)
    addresses = sc.Addresses(rng)
    for scenario in sc.SCENARIOS:
        for step in scenario.plan(addresses, rng):
            for line in step.lines(datetime.now(timezone.utc)):
                ip = ipaddress.ip_address(line.split(" ", 1)[0])
                assert any(ip in block for block in DOCUMENTATION_BLOCKS), f"{ip} no es de un bloque de documentación"


def test_attackers_and_clients_do_not_share_addresses():
    addresses = sc.Addresses(random.Random(5))
    attackers = {addresses.attacker() for _ in range(40)}
    clients = set(addresses.clients(10))
    assert attackers.isdisjoint(clients)
    assert all(a.startswith(sc.ATTACKER_NETS) for a in attackers)
    assert all(c.startswith(sc.CLIENT_NET) for c in clients)


def test_the_pool_of_attackers_is_reused_only_after_it_runs_out():
    addresses = sc.Addresses(random.Random(1))
    first_round = [addresses.attacker() for _ in range(480)]
    assert len(set(first_round)) == 480
    assert addresses.attacker() in first_round  # se agotaron: vuelve a empezar en lugar de fallar


def test_log_line_uses_nginx_format_and_utc_in_english_month_names():
    when = datetime(2026, 11, 3, 4, 5, 6, tzinfo=timezone.utc)
    line = sc.log_line("198.51.100.9", "GET", "/x?y=1", 200, "ua/1", size=77, now=when)
    assert line == '198.51.100.9 - - [03/Nov/2026:04:05:06 +0000] "GET /x?y=1 HTTP/1.1" 200 77 "-" "ua/1"'


def test_every_rule_the_engine_can_fire_has_a_label_for_the_console():
    fired = {rule for scenario in sc.SCENARIOS for step in scenario.plan(sc.Addresses(random.Random(2)), random.Random(2))
             for rule in step.expect}
    assert fired <= set(sc.RULE_LABELS)
