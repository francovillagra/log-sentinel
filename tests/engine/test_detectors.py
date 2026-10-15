import pytest

from engine.detectors.brute_force import BruteForceDetector
from engine.detectors.rate_anomaly import RateAnomalyDetector
from engine.rules import BruteForceConfig, RateAnomalyConfig
from tests.corpus import ATTACKS, BENIGN, LOGIN_PATHS, USER_AGENTS
from tests.engine.helpers import new_engine, nginx_line


def rules(line: str) -> list[str]:
    _event, alerts = new_engine().process_line(line)
    return sorted(a.rule_id for a in alerts)


@pytest.mark.parametrize("nombre, objetivo, regla", ATTACKS, ids=[a[0] for a in ATTACKS])
def test_detecta_el_ataque_aunque_venga_ofuscado(nombre, objetivo, regla):
    assert regla in rules(nginx_line(objetivo))


@pytest.mark.parametrize("nombre, ua, regla", USER_AGENTS, ids=[u[0] for u in USER_AGENTS])
def test_user_agents(nombre, ua, regla):
    assert rules(nginx_line("/", ua=ua)) == ([regla] if regla else [])


@pytest.mark.parametrize("objetivo", BENIGN)
def test_trafico_legitimo_no_genera_alertas(objetivo):
    assert rules(nginx_line(objetivo)) == []


def test_la_evidencia_es_el_fragmento_detectado():
    _ev, alerts = new_engine().process_line(nginx_line("/p?id=1+UNION+SELECT+1"))
    assert [(a.rule_id, a.evidence) for a in alerts] == [("sqli", "UNION SELECT")]


def test_el_atacante_no_puede_inflar_la_alerta():
    ua = "sqlmap " + "A" * 5000
    _ev, alerts = new_engine().process_line(nginx_line("/", ua=ua))
    assert len(alerts[0].evidence) <= 300 and len(alerts[0].raw_event) <= 2048


def test_un_nul_en_el_user_agent_no_llega_a_la_alerta():
    _ev, alerts = new_engine().process_line(nginx_line("/", ua="sqlmap\x00x"))
    assert "\x00" not in alerts[0].evidence and "\x00" not in alerts[0].raw_event


# --- fuerza bruta -------------------------------------------------------------------------------------------------------

def fallos(path: str, n: int, ip: str = "198.51.100.77", status: int = 401, start: int = 0, step: int = 1):
    eng = new_engine()
    out = []
    for i in range(n):
        s = start + i * step
        _ev, alerts = eng.process_line(nginx_line(path, status=status, ip=ip, time=f"01/Jan/2026:12:{s // 60:02d}:{s % 60:02d} +0000"))
        out += [a.rule_id for a in alerts]
    return out


@pytest.mark.parametrize("ruta", LOGIN_PATHS)
def test_fuerza_bruta_en_cualquier_ruta_de_login(ruta):
    assert fallos(ruta, 8).count("brute_force") == 1


def test_fuerza_bruta_umbral_y_ventana():
    assert fallos("/login", 4) == []                       # 4 fallos: todavía no
    assert fallos("/login", 5).count("brute_force") == 1   # el 5.º
    assert fallos("/login", 12, step=30) == []             # un fallo cada 30 s: nunca 5 dentro de 60 s... salvo 3 por minuto
    assert fallos("/login", 8, status=200) == []           # logins exitosos no cuentan
    assert fallos("/index.html", 8) == []                  # fuera de las rutas de autenticación
    assert fallos("/login", 8, status=403).count("brute_force") == 1


def test_fuerza_bruta_vuelve_a_avisar_despues_de_la_ventana():
    cfg = BruteForceConfig(threshold=3, window_seconds=10)
    det, eng = BruteForceDetector(cfg), new_engine()
    eng._detectors = [det]
    got = []
    for s in [0, 1, 2, 3, 4, 30, 31, 32]:
        _ev, alerts = eng.process_line(nginx_line("/login", status=401, time=f"01/Jan/2026:12:00:{s:02d} +0000"))
        got.append(bool(alerts))
    assert got == [False, False, True, False, False, False, False, True]


def test_fuerza_bruta_cada_ip_por_separado():
    eng = new_engine()
    for i in range(10):
        _ev, alerts = eng.process_line(nginx_line("/login", status=401, ip=f"10.0.0.{i}"))
        assert not [a for a in alerts if a.rule_id == "brute_force"]


# --- ráfaga de peticiones ---------------------------------------------------------------------------------------------------

def test_rate_anomaly_umbral():
    cfg = RateAnomalyConfig(threshold=100, window_seconds=10)
    eng = new_engine()
    eng._detectors = [RateAnomalyDetector(cfg)]
    fired = [i for i in range(120) if eng.process_line(nginx_line(f"/p/{i}"))[1]]
    assert fired == [99]  # la petición n.º 100 dentro de la misma ventana, una sola vez
