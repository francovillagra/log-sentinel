"""Escenarios de práctica de la consola de la demo.

Un escenario arma líneas de log con el formato de nginx (combined) y nada más: no abre conexiones ni toca archivos. Quien las
envía es server.py. Por eso se pueden probar solos contra el motor real (tests/demo/test_scenarios.py): cada botón de la
consola tiene que disparar la regla que promete, y el tráfico normal no puede disparar ninguna.

Las direcciones salen de los bloques reservados para documentación (RFC 5737): no pertenecen a nadie, así que ningún tráfico
de práctica puede confundirse con el de un tercero real.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

CLIENT_NET = "192.0.2."                          # TEST-NET-1: visitantes y clientes comunes
ATTACKER_NETS = ("198.51.100.", "203.0.113.")    # TEST-NET-2 y TEST-NET-3: atacantes de práctica

# nginx escribe el mes en inglés y abreviado; no se usa strftime("%b") porque depende del idioma del sistema.
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

BROWSERS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 "
    "Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
)
SCRIPT_UA = "python-requests/2.31.0"   # lo que usa un programa casero para probar claves; no es un escáner conocido

# Nombre en palabras de cliente de cada regla del motor, y su severidad tal como la muestra la consola.
RULE_LABELS = {
    "brute_force": "Prueba de contraseñas (fuerza bruta)",
    "sqli": "Inyección SQL",
    "xss": "Script malicioso (XSS)",
    "path_traversal": "Lectura de archivos privados",
    "suspicious_ua": "Herramienta de ataque conocida",
    "rate_anomaly": "Ráfaga anormal de visitas",
}
SEVERITY_LABELS = {"CRITICAL": "crítica", "HIGH": "alta", "MEDIUM": "media", "LOW": "baja", "INFO": "informativa"}


def log_line(ip: str, method: str, target: str, status: int, ua: str, *, size: int = 512, referer: str = "-",
             now: Optional[datetime] = None) -> str:
    """Una línea como la registraría nginx: la dirección, la hora (UTC), el pedido, el estado, el tamaño y el navegador."""
    when = (now or datetime.now(timezone.utc))
    when = when.replace(tzinfo=timezone.utc) if when.tzinfo is None else when.astimezone(timezone.utc)
    stamp = f"{when.day:02d}/{_MONTHS[when.month - 1]}/{when.year}:{when:%H:%M:%S} +0000"
    return f'{ip} - - [{stamp}] "{method} {target} HTTP/1.1" {status} {size} "{referer}" "{ua}"'


class Addresses:
    """Reparte direcciones de práctica.

    Cada clic recibe un atacante distinto: los detectores con estado (fuerza bruta, ráfaga) avisan una sola vez por dirección
    y ventana, así que repetir la misma dirección haría que el segundo clic no mostrara nada.
    """

    def __init__(self, rng: random.Random) -> None:
        self._rng = rng
        self._used: set[str] = set()
        self._pool = [f"{net}{host}" for net in ATTACKER_NETS for host in range(10, 250)]

    def attacker(self) -> str:
        free = [ip for ip in self._pool if ip not in self._used]
        if not free:  # se agotaron las 480: se vuelve a empezar
            self._used.clear()
            free = self._pool
        ip = self._rng.choice(free)
        self._used.add(ip)
        return ip

    def clients(self, count: int) -> list[str]:
        return [f"{CLIENT_NET}{host}" for host in self._rng.sample(range(10, 250), count)]


@dataclass(frozen=True)
class Step:
    """Un envío a la API: `lines(ahora)` arma las líneas justo antes de mandarlas, para que lleven la hora real."""

    what: str                                   # qué se manda, en palabras de cliente
    ip: str
    lines: Callable[[datetime], tuple[str, ...]]
    expect: tuple[str, ...] = ()                # reglas que tienen que saltar con este envío (vacío: ninguna)
    pause: float = 0.0                          # segundos de espera después de enviar (ritmo de la secuencia)


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    story: str                                  # qué pasa en el mundo real, en una frase
    kind: str                                   # "normal" | "attack" | "campaign": solo cambia el color del botón
    plan: Callable[[Addresses, random.Random], list[Step]]


# --- los pedidos de cada ataque (varios por tipo, para que dos clics no sean idénticos) --------------------------------

_SQLI_TARGETS = (
    "/producto?id=1%27%20UNION%20SELECT%20usuario,clave%20FROM%20clientes--%20-",
    "/producto?id=1%20OR%201=1",
    "/buscar?q=%27%20OR%20%271%27=%271",
    "/producto?id=1;DROP%20TABLE%20clientes",
)
_XSS_TARGETS = (
    "/buscar?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
    "/buscar?q=%3Cimg%20src=x%20onerror=alert(1)%3E",
    "/comentarios?texto=%3Csvg/onload=alert(1)%3E",
)
_FILE_TARGETS = (
    "/descargar?archivo=../../../../etc/passwd",
    "/.env",
    "/.git/config",
    "/wp-config.php.bak",
)
_SCANNER_UAS = (
    "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)",
    "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
)


def _one(ip: str, method: str, target: str, status: int, ua: str, size: int = 512) -> Callable[[datetime], tuple[str, ...]]:
    return lambda now: (log_line(ip, method, target, status, ua, size=size, now=now),)


def _many(count: int, ip: str, method: str, target: Callable[[int], str], status: int, ua: str) -> Callable[[datetime], tuple[str, ...]]:
    return lambda now: tuple(log_line(ip, method, target(i), status, ua, size=200 + (i * 7) % 60, now=now) for i in range(count))


def _passwords_step(ip: str, rng: random.Random, pause: float = 0.0, count: int = 8) -> Step:
    return Step(f"{count} intentos de ingreso fallidos en el login", ip,
                _many(count, ip, "POST", lambda i: "/login", 401, SCRIPT_UA), ("brute_force",), pause)


def _sqli_step(ip: str, rng: random.Random, pause: float = 0.0) -> Step:
    return Step("Pedido con comandos de base de datos escondidos en la dirección", ip,
                _one(ip, "GET", rng.choice(_SQLI_TARGETS), 200, rng.choice(BROWSERS)), ("sqli",), pause)


def _xss_step(ip: str, rng: random.Random, pause: float = 0.0) -> Step:
    return Step("Búsqueda que lleva un script dentro", ip,
                _one(ip, "GET", rng.choice(_XSS_TARGETS), 200, rng.choice(BROWSERS)), ("xss",), pause)


def _files_step(ip: str, rng: random.Random, pause: float = 0.0) -> Step:
    return Step("Pedido de un archivo interno del servidor", ip,
                _one(ip, "GET", rng.choice(_FILE_TARGETS), 404, rng.choice(BROWSERS)), ("path_traversal",), pause)


def _tool_step(ip: str, rng: random.Random, pause: float = 0.0) -> Step:
    return Step("Visita de un programa de ataque conocido a la zona de administración", ip,
                _one(ip, "GET", "/admin/", 403, rng.choice(_SCANNER_UAS)), ("suspicious_ua",), pause)


def _flood_step(ip: str, rng: random.Random, pause: float = 0.0) -> Step:
    count = 120
    return Step(f"{count} visitas en el mismo segundo", ip,
                _many(count, ip, "GET", lambda i: f"/productos?pagina={i}", 200, rng.choice(BROWSERS)), ("rate_anomaly",), pause)


# --- los escenarios ----------------------------------------------------------------------------------------------------

_PAGES = (
    ("GET", "/", 200), ("GET", "/productos", 200), ("GET", "/productos/1042", 200), ("GET", "/contacto", 200),
    ("GET", "/carrito", 200), ("POST", "/carrito/agregar", 200), ("GET", "/static/app.css", 304),
    ("GET", "/favicon.ico", 200), ("POST", "/login", 200), ("GET", "/mi-cuenta", 200), ("GET", "/robots.txt", 200),
)


def _normal_plan(addr: Addresses, rng: random.Random) -> list[Step]:
    clients = addr.clients(10)
    visits = [(rng.choice(clients), *rng.choice(_PAGES), rng.choice(BROWSERS)) for _ in range(24)]

    def lines(now: datetime) -> tuple[str, ...]:
        return tuple(log_line(ip, method, target, status, ua, size=rng.randint(300, 9000), now=now)
                     for ip, method, target, status, ua in visits)

    return [Step("24 visitas comunes de clientes: navegar, mirar productos, comprar", CLIENT_NET + "0/24", lines)]


def _make_single(step_fn: Callable[[str, random.Random, float], Step]) -> Callable[[Addresses, random.Random], list[Step]]:
    return lambda addr, rng: [step_fn(addr.attacker(), rng, 0.0)]


def _campaign_plan(addr: Addresses, rng: random.Random) -> list[Step]:
    ip, pause = addr.attacker(), 2.5
    return [
        _tool_step(ip, rng, pause),
        _passwords_step(ip, rng, pause, count=7),
        _sqli_step(ip, rng, pause),
        _files_step(ip, rng, pause),
        _flood_step(ip, rng, 0.0),
    ]


SCENARIOS: tuple[Scenario, ...] = (
    Scenario("normal", "Un día normal en el sitio",
             "Clientes que navegan y compran. No debe haber ningún aviso.",
             "normal", _normal_plan),
    Scenario("passwords", "Alguien prueba contraseñas",
             "Un programa prueba claves, una tras otra, para entrar a una cuenta.", "attack",
             _make_single(_passwords_step)),
    Scenario("sqli", "Intentan sacar datos de clientes",
             "Órdenes escondidas en una dirección web para que el sitio entregue datos que no debe.",
             "attack", _make_single(_sqli_step)),
    # La prueba que junta todo va cuarta: con las tres anteriores alcanza para contar la historia, y así queda a la vista
    # aunque la ventana sea chica; las pruebas sueltas que faltan van debajo.
    Scenario("campaign", "Ataque en varias etapas",
             "Un mismo atacante revisa, prueba claves, saca datos, lee archivos y satura. El panel lo agrupa.",
             "campaign", _campaign_plan),
    Scenario("xss", "Meten un script en el buscador",
             "Código colado en un campo del sitio para que corra en el navegador de otras personas.",
             "attack", _make_single(_xss_step)),
    Scenario("files", "Intentan leer archivos privados",
             "Piden archivos internos del servidor, como el de las claves.",
             "attack", _make_single(_files_step)),
    Scenario("tool", "Un programa de ataque revisa el sitio",
             "Los programas de hackeo conocidos buscan puntos débiles y se presentan con su nombre.",
             "attack", _make_single(_tool_step)),
    Scenario("flood", "Ráfaga de visitas",
             "Cientos de pedidos en segundos desde un mismo origen, para dejar el sitio sin servicio.",
             "attack", _make_single(_flood_step)),
)
BY_ID = {s.id: s for s in SCENARIOS}
