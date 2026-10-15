import random
from collections import defaultdict, deque
from datetime import datetime, timedelta

from engine.windows import SlidingThreshold

T0 = datetime(2026, 1, 1, 12, 0, 0)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def test_avisa_una_vez_por_ventana():
    w = SlidingThreshold(threshold=3, window_seconds=10, max_keys=100)
    assert [w.hit("ip", at(s)) for s in (0, 1, 2, 3, 4)] == [None, None, 3, None, None]
    assert w.hit("ip", at(20)) is None          # los eventos de arriba ya salieron de la ventana de 10 s
    assert w.hit("ip", at(21)) is None
    assert w.hit("ip", at(22)) == 3             # tres eventos en 10 s y pasó el silencio de la alerta anterior


def test_las_ips_son_independientes():
    w = SlidingThreshold(threshold=2, window_seconds=10, max_keys=100)
    assert w.hit("a", at(0)) is None and w.hit("b", at(0)) is None
    assert w.hit("a", at(1)) == 2 and w.hit("b", at(1)) == 2


def test_la_memoria_esta_acotada():
    w = SlidingThreshold(threshold=5, window_seconds=60, max_keys=1000)
    for i in range(50_000):
        w.hit(f"10.{i // 65536}.{i // 256 % 256}.{i % 256}", at(i % 10))
    assert len(w) == 1000


def test_se_olvida_la_ip_menos_reciente_no_la_activa():
    w = SlidingThreshold(threshold=2, window_seconds=60, max_keys=3)
    w.hit("vieja", at(0))
    w.hit("b", at(1)); w.hit("c", at(2))
    w.hit("vieja", at(3))          # vuelve a estar activa: la menos reciente pasa a ser "b"
    w.hit("d", at(4))              # entra una cuarta: sale "b"
    assert w.hit("vieja", at(5)) is None   # "vieja" conserva su historial (ya avisó en at(3)), no se reinició
    assert w.hit("b", at(6)) is None       # "b" empieza de cero


def test_una_ip_no_acumula_mas_marcas_que_el_umbral():
    w = SlidingThreshold(threshold=5, window_seconds=3600, max_keys=10)
    for i in range(100_000):
        w.hit("atacante", at(i * 0.001))
    assert len(w._entries["atacante"].times) <= 5


def reference(events, threshold, window):
    """El algoritmo original (deque por IP, sin tope), para comprobar que la versión acotada avisa en los mismos momentos."""
    windows, last, fired = defaultdict(deque), {}, []
    for i, (ip, ts) in enumerate(events):
        w = windows[ip]
        cutoff = ts - timedelta(seconds=window)
        while w and w[0] < cutoff:
            w.popleft()
        w.append(ts)
        if len(w) < threshold:
            continue
        if ip in last and (ts - last[ip]).total_seconds() < window:
            continue
        last[ip] = ts
        fired.append(i)
    return fired


def test_avisa_en_los_mismos_momentos_que_el_algoritmo_original():
    rng = random.Random(1234)
    for _ in range(30):
        threshold, window = rng.choice([(3, 5), (5, 60), (10, 10), (100, 10)])
        ips = [f"ip{n}" for n in range(rng.choice([1, 3, 20]))]
        t, events = 0.0, []
        for _ in range(3000):
            t += rng.choice([0.0, 0.01, 0.1, 0.5, 1.0, 5.0])
            events.append((rng.choice(ips), at(t)))
        w = SlidingThreshold(threshold, window, max_keys=10_000)
        got = [i for i, (ip, ts) in enumerate(events) if w.hit(ip, ts) is not None]
        assert got == reference(events, threshold, window), (threshold, window)
