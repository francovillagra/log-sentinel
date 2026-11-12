"""Consola de práctica de la demo de Log-Sentinel.

Una página con botones en lenguaje de cliente. Cada botón manda a la API (POST /api/v1/ingest) líneas de log de práctica, con
direcciones ficticias, y muestra qué detectó el sistema; el aviso aparece también, en vivo, en el panel.

Usa solo la biblioteca estándar: no hay nada que instalar y el código entero se lee en un rato. Corre dentro de la demo
(docker compose) y solo se publica en 127.0.0.1 de la computadora. Aun así rechaza pedidos de otros sitios web abiertos en el
mismo navegador (ver `_host_allowed` y el chequeo de Origin en `do_POST`). Ver demo/README.md.
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import parse_qs, urlsplit

try:  # importado como paquete (las pruebas)
    from . import scenarios as sc
except ImportError:  # corriendo como script dentro del contenedor
    import scenarios as sc

log = logging.getLogger("consola")

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_EVENTS = 300
LINES_PER_REQUEST = 500        # la API acepta hasta 1000 líneas por pedido (MAX_INGEST_LINES)
PREVIEW_LINES = 5              # cuántas líneas se muestran en "ver lo que se envió"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}


@dataclass(frozen=True)
class Config:
    api_url: str = "http://api:8000"
    panel_url: str = "http://localhost:4001"
    public_port: int = 4000          # el puerto con el que el navegador abre la consola (el publicado por docker)
    secrets_dir: Path = Path("/run/demo")
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080

    @classmethod
    def from_env(cls) -> "Config":
        env = os.environ.get
        return cls(
            api_url=env("DEMO_API_URL", cls.api_url).rstrip("/"),
            panel_url=env("DEMO_PANEL_URL", cls.panel_url).rstrip("/"),
            public_port=int(env("DEMO_CONSOLE_PUBLIC_PORT", str(cls.public_port))),
            secrets_dir=Path(env("DEMO_SECRETS_DIR", str(cls.secrets_dir))),
            listen_host=env("DEMO_LISTEN_HOST", cls.listen_host),
            listen_port=int(env("DEMO_LISTEN_PORT", str(cls.listen_port))),
        )

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return frozenset({f"localhost:{self.public_port}", f"127.0.0.1:{self.public_port}"})

    @property
    def allowed_origins(self) -> frozenset[str]:
        return frozenset(f"http://{host}" for host in self.allowed_hosts)


def read_secret(directory: Path, name: str) -> str:
    """Lee una credencial del volumen que llena `make_secrets.py`. Se lee en cada uso: nunca queda en memoria de más."""
    try:
        return (directory / name).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


class IngestError(Exception):
    """El envío a la API falló; el mensaje es para mostrarle a quien usa la consola (sin claves ni detalles internos)."""


class ApiSender:
    """Manda líneas a POST /api/v1/ingest con la clave de ingesta de la demo."""

    def __init__(self, config: Config) -> None:
        self._config = config

    def __call__(self, lines: list[str]) -> dict:
        key = read_secret(self._config.secrets_dir, "ingest_api_key")
        if not key:
            raise IngestError("Las claves de la demo todavía no están listas. Esperar unos segundos y probar de nuevo.")
        merged: dict = {"processed": 0, "alerts_fired": 0, "alerts": []}
        for start in range(0, len(lines), LINES_PER_REQUEST):
            part = self._post(key, lines[start:start + LINES_PER_REQUEST])
            merged["processed"] += int(part.get("processed", 0))
            merged["alerts_fired"] += int(part.get("alerts_fired", 0))
            merged["alerts"].extend(part.get("alerts", []))
        return merged

    def _post(self, key: str, lines: list[str]) -> dict:
        request = urllib.request.Request(
            f"{self._config.api_url}/api/v1/ingest",
            data=json.dumps({"lines": lines}).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "X-API-Key": key},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise IngestError(
                    "La API rechazó la clave de la demo. Apagar todo con «docker compose down -v» y volver a encender."
                ) from None
            raise IngestError(f"La API respondió con el error {exc.code}.") from None
        except (OSError, ValueError):
            raise IngestError("No se pudo hablar con la API. Puede estar todavía arrancando: esperar unos segundos.") from None


def api_ready(config: Config) -> bool:
    try:
        with urllib.request.urlopen(f"{config.api_url}/health", timeout=1.5) as response:
            return response.status == 200
    except (OSError, ValueError):
        return False


class Runner:
    """Ejecuta un escenario por vez en un hilo propio y guarda lo que va pasando para que la página lo muestre."""

    def __init__(self, send: Callable[[list[str]], dict], *, rng: Optional[random.Random] = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self._send = send
        self._rng = rng or random.Random()
        self._sleep = sleep
        self._clock = clock
        self._addresses = sc.Addresses(self._rng)
        self._lock = threading.Lock()
        self._events: list[dict] = []
        self._seq = 0
        self._running = False

    def start(self, scenario_id: str, *, wait: bool = False) -> str:
        """'started', 'busy' (ya hay una prueba en curso) o 'unknown'. Con wait=True espera a que termine (para las pruebas)."""
        scenario = sc.BY_ID.get(scenario_id)
        if scenario is None:
            return "unknown"
        with self._lock:
            if self._running:
                return "busy"
            self._running = True
        if wait:
            self._run(scenario)
        else:
            threading.Thread(target=self._run, args=(scenario,), daemon=True).start()
        return "started"

    def events_since(self, since: int) -> tuple[list[dict], bool]:
        with self._lock:
            return [e for e in self._events if e["n"] > since], self._running

    def _add(self, event: dict) -> None:
        with self._lock:
            self._seq += 1
            event["n"] = self._seq
            self._events.append(event)
            del self._events[:-MAX_EVENTS]

    def _run(self, scenario: "sc.Scenario") -> None:
        try:
            steps = scenario.plan(self._addresses, self._rng)
            for index, step in enumerate(steps, 1):
                lines = step.lines(self._clock())
                event = {
                    "t": self._clock().isoformat(timespec="seconds"),
                    "scenario": scenario.id, "title": scenario.title,
                    "step": index, "steps": len(steps),
                    "what": step.what, "ip": step.ip, "sent": len(lines), "expect": list(step.expect),
                    "lines": [line[:300] for line in lines[:PREVIEW_LINES]],
                    "more_lines": max(0, len(lines) - PREVIEW_LINES),
                    "alerts": [], "ok": False, "error": None,
                }
                try:
                    result = self._send(list(lines))
                except IngestError as exc:
                    event["error"] = str(exc)
                    self._add(event)
                    break  # sin API no tiene sentido seguir con el resto de la secuencia
                alerts = [_alert_view(a) for a in result.get("alerts", [])]
                detected = {a["rule_id"] for a in alerts}
                event["alerts"] = alerts
                # Con reglas esperadas: tienen que haber saltado todas. Sin reglas esperadas (tráfico normal): ninguna.
                event["ok"] = set(step.expect) <= detected and (bool(step.expect) or not alerts)
                self._add(event)
                if index < len(steps) and step.pause:
                    self._sleep(step.pause)
        except Exception:  # noqa: BLE001 - la consola no puede quedar trabada en "ocupado" por un error propio
            log.exception("Falló el escenario %s", scenario.id)
            self._add({"t": self._clock().isoformat(timespec="seconds"), "scenario": scenario.id, "title": scenario.title,
                       "step": 1, "steps": 1, "what": "Error propio de la consola", "ip": "", "sent": 0, "expect": [], "lines": [],
                       "more_lines": 0, "alerts": [], "ok": False,
                       "error": "La consola tuvo un error inesperado (el detalle está en su registro)."})
        finally:
            with self._lock:
                self._running = False


def _alert_view(alert: dict) -> dict:
    rule = str(alert.get("rule_id", ""))
    severity = str(alert.get("severity", ""))
    return {
        "rule_id": rule,
        "label": sc.RULE_LABELS.get(rule, rule),
        "severity": severity,
        "severity_label": sc.SEVERITY_LABELS.get(severity, severity.lower()),
        "src_ip": str(alert.get("src_ip", "")),
        "evidence": str(alert.get("evidence", ""))[:240],
    }


@dataclass(frozen=True)
class Asset:
    body: bytes
    content_type: str


def load_assets() -> dict[str, Asset]:
    files = {
        "/": ("index.html", "text/html; charset=utf-8"),
        "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        "/style.css": ("style.css", "text/css; charset=utf-8"),
    }
    return {url: Asset((STATIC_DIR / name).read_bytes(), ctype) for url, (name, ctype) in files.items()}


def create_server(config: Config, runner: Runner, ready: Optional[Callable[[], bool]] = None) -> ThreadingHTTPServer:
    assets = load_assets()
    is_ready = ready or (lambda: api_ready(config))

    class Handler(BaseHTTPRequestHandler):
        server_version = "consola"
        sys_version = ""

        # -- registro y respuestas ------------------------------------------------------------------------------------
        def log_request(self, code="-", size="-") -> None:
            # La página consulta /api/events varias veces por segundo: no llenar el registro con eso.
            if str(code) == "200" and self.path.split("?")[0] in ("/api/events", "/api/state", "/healthz"):
                return
            super().log_request(code, size)

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            sys.stderr.write("%s\n" % (format % args))

        def send_response(self, code, message=None) -> None:
            # Igual que la clase base, pero sin la cabecera Server: no hace falta anunciar qué es.
            self.log_request(code)
            self.send_response_only(code, message)

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in SECURITY_HEADERS.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: dict) -> None:
            self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        # -- protección contra otros sitios abiertos en el mismo navegador ----------------------------------------------
        def _host_allowed(self) -> bool:
            # Un sitio ajeno que apunte su dominio a 127.0.0.1 (DNS rebinding) llega con su propio Host: se rechaza.
            return self.headers.get("Host", "").lower() in config.allowed_hosts

        # -- rutas ----------------------------------------------------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            url = urlsplit(self.path)
            if url.path == "/healthz":  # sin chequeo de Host: lo consulta docker desde dentro del contenedor
                return self._send(200, b"ok", "text/plain; charset=utf-8")
            if not self._host_allowed():
                return self._json(421, {"error": "host no permitido"})
            asset = assets.get(url.path)
            if asset:
                return self._send(200, asset.body, asset.content_type)
            if url.path == "/api/state":
                return self._json(200, self._state())
            if url.path == "/api/events":
                try:
                    since = int(parse_qs(url.query).get("since", ["0"])[0])
                except ValueError:
                    since = 0
                events, running = runner.events_since(since)
                return self._json(200, {"events": events, "running": running})
            self._json(404, {"error": "no existe"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_allowed():
                return self._json(421, {"error": "host no permitido"})
            # Los navegadores mandan siempre Origin en un POST. Si no es el de esta consola, lo mandó otra página.
            if self.headers.get("Origin") not in config.allowed_origins:
                return self._json(403, {"error": "origen no permitido"})
            match = re.fullmatch(r"/api/run/([a-z]{1,20})", urlsplit(self.path).path)
            if not match:
                return self._json(404, {"error": "no existe"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length > 1024:
                return self._json(413, {"error": "pedido demasiado grande"})
            if length:
                self.rfile.read(length)
            outcome = runner.start(match.group(1))
            self._json({"started": 202, "busy": 409, "unknown": 404}[outcome], {"result": outcome})

        def _state(self) -> dict:
            email = read_secret(config.secrets_dir, "admin_email")
            password = read_secret(config.secrets_dir, "admin_password")
            return {
                "scenarios": [{"id": s.id, "title": s.title, "story": s.story, "kind": s.kind} for s in sc.SCENARIOS],
                "panel_url": config.panel_url,
                "login": {"email": email, "password": password} if email and password else None,
                "api_ready": is_ready(),
            }

    return ThreadingHTTPServer((config.listen_host, config.listen_port), Handler)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    config = Config.from_env()
    server = create_server(config, Runner(ApiSender(config)))
    # docker stop manda SIGTERM; como proceso 1 el intérprete lo ignoraría y la parada tardaría diez segundos.
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    print(f"Consola de práctica lista: http://localhost:{config.public_port}", flush=True)
    print(f"Panel de avisos: {config.panel_url}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
