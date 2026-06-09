"""
log-sentinel traffic simulator.

Generates a continuous mix of benign and malicious HTTP log lines and POSTs them
to the production ingest API, so the live dashboard comes alive without manual
curls. Runs locally — only talks to the Railway API, never Supabase directly.

Usage:
    python simulator/run.py
    RATE=5 ATTACK_RATIO=0.5 python simulator/run.py
"""

import asyncio
import logging
import os
import random
from datetime import datetime, timezone

import httpx

# --- configuration (env or defaults) ----------------------------------------
INGEST_URL = os.getenv("INGEST_URL", "https://log-sentinel-production.up.railway.app")
API_KEY = os.getenv("INGEST_API_KEY", "sentinel-2026")
RATE = float(os.getenv("RATE", "2.0"))                  # requests per second
ATTACK_RATIO = float(os.getenv("ATTACK_RATIO", "0.3"))  # share of attack traffic

INGEST_ENDPOINT = f"{INGEST_URL.rstrip('/')}/api/v1/ingest"

# Detector thresholds the bursts must exceed to actually fire (see engine/rules.py):
#   rate_anomaly = 100 requests / 10s   → send 105 in one batch
#   brute_force  = 5 failed auth / 60s  → send 6 in one batch
RATE_ANOMALY_BURST = 105
BRUTE_FORCE_BURST = 6

NORMAL_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

logging.basicConfig(level=logging.INFO, format="%(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("simulator")


# --- log-line builders -------------------------------------------------------
def _now() -> str:
    return datetime.now(timezone.utc).strftime(_TIME_FMT)


def _line(ip: str, method: str, request: str, status: int,
          ua: str, body_bytes: int = 0, referer: str = "-") -> str:
    """Build one Nginx combined-format log line."""
    return (
        f'{ip} - - [{_now()}] "{method} {request} HTTP/1.1" '
        f'{status} {body_bytes} "{referer}" "{ua}"'
    )


# --- attack scenarios --------------------------------------------------------
# Each returns (rule_id, src_ip, payload) where payload is the ingest body.
def _attack_brute_force():
    ip = "192.168.1.50"
    lines = [_line(ip, "POST", "/login", 401, NORMAL_UA) for _ in range(BRUTE_FORCE_BURST)]
    return "brute_force", ip, {"lines": lines}


def _attack_sqli():
    ip = "10.0.0.1"
    line = _line(ip, "GET", "/products?id=1 UNION SELECT * FROM users--", 200, NORMAL_UA)
    return "sqli", ip, {"line": line}


def _attack_path_traversal():
    ip = "172.16.0.1"
    line = _line(ip, "GET", "/../../../etc/passwd", 404, NORMAL_UA)
    return "path_traversal", ip, {"line": line}


def _attack_xss():
    ip = "10.0.0.2"
    line = _line(ip, "GET", "/search?q=<script>alert(1)</script>", 200, NORMAL_UA)
    return "xss", ip, {"line": line}


def _attack_suspicious_ua():
    ip = "45.33.32.156"
    line = _line(ip, "GET", "/admin", 200, "sqlmap/1.7")
    return "suspicious_ua", ip, {"line": line}


def _attack_rate_anomaly():
    ip = "203.0.113.42"
    lines = [_line(ip, "GET", f"/api/data?p={i}", 200, NORMAL_UA)
             for i in range(RATE_ANOMALY_BURST)]
    return "rate_anomaly", ip, {"lines": lines}


ATTACKS = [
    _attack_brute_force,
    _attack_sqli,
    _attack_path_traversal,
    _attack_xss,
    _attack_suspicious_ua,
    _attack_rate_anomaly,
]


# --- normal traffic ----------------------------------------------------------
_NORMAL = [
    ("GET", "/", 200, NORMAL_UA),
    ("GET", "/api/health", 200, "curl/7.88.1"),
    ("POST", "/api/login", 200, NORMAL_UA),
]


def _normal_traffic():
    method, request, status, ua = random.choice(_NORMAL)
    ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
    return ip, {"line": _line(ip, method, request, status, ua)}


# --- runner ------------------------------------------------------------------
async def _send(client: httpx.AsyncClient, payload: dict) -> dict:
    resp = await client.post(
        INGEST_ENDPOINT,
        json=payload,
        headers={"X-API-Key": API_KEY},
    )
    resp.raise_for_status()
    return resp.json()


async def run() -> None:
    interval = 1.0 / RATE if RATE > 0 else 0.5
    log.info(
        "simulator → %s | rate=%.1f/s | attack_ratio=%.2f | Ctrl+C to stop",
        INGEST_ENDPOINT, RATE, ATTACK_RATIO,
    )
    async with httpx.AsyncClient(timeout=15.0) as client:
        while True:
            try:
                if random.random() < ATTACK_RATIO:
                    rule, ip, payload = random.choice(ATTACKS)()
                    resp = await _send(client, payload)
                    fired = resp.get("alerts_fired", 0)
                    log.info("%s | ATTACK | %-14s | %-15s | fired=%s",
                             _now(), rule, ip, fired)
                else:
                    ip, payload = _normal_traffic()
                    await _send(client, payload)
                    log.info("%s | NORMAL | %-14s | %-15s |", _now(), "-", ip)
            except httpx.HTTPError as exc:
                log.warning("request failed: %s — continuing", exc)
            await asyncio.sleep(interval)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        log.info("simulator stopped")
