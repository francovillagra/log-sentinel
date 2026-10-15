import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from functools import cached_property
from typing import Optional

from engine.normalize import Target, normalize_target


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Tope de caracteres que se guardan/transmiten de cada campo de una alerta. Los campos salen de la línea de log, o sea del
# atacante: sin tope, un user-agent de 10 MB se copiaría tal cual a Redis (10 000 entradas), a Postgres y a cada dashboard.
MAX_ALERT_FIELD_CHARS = {
    "rule_id": 64,
    "title": 128,
    "src_ip": 64,
    "description": 300,
    "evidence": 300,
    "raw_event": 2048,
}

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def clean_text(value: object, limit: int) -> str:
    """Deja `value` listo para guardarse y mostrarse: texto, sin caracteres de control (un NUL rompe el INSERT en Postgres
    y el alerta se perdía), sin sustitutos sueltos (rompen la codificación UTF-8) y con un largo máximo."""
    text = value if isinstance(value, str) else str(value)
    text = text.encode("utf-8", "backslashreplace").decode("utf-8")
    text = _CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", text)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


@dataclass
class LogEvent:
    ts: datetime
    src_ip: str
    method: str
    path: str
    query: str
    status: int
    user_agent: str
    bytes_sent: int
    referer: Optional[str]
    raw: str

    @cached_property
    def target(self) -> Target:
        """Ruta + query decodificadas (una sola vez por evento, aunque lo consulten varios detectores)."""
        return normalize_target(self.path, self.query)


@dataclass
class Alert:
    ts: datetime
    src_ip: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    evidence: str
    raw_event: str

    def __post_init__(self) -> None:
        for name, limit in MAX_ALERT_FIELD_CHARS.items():
            setattr(self, name, clean_text(getattr(self, name), limit))
