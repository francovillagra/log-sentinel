import re
from datetime import datetime, timezone
from typing import Optional

from engine.models import LogEvent
from engine.parsers.base import Parser

# $remote_addr - $remote_user [$time_local] "$request" $status $bytes "$referer" "$ua"
#
# La petición se captura entera (`[^"]*`, nginx escapa las comillas como \x22) y se separa en método, ruta y protocolo con
# métodos de str, no con la regex: el patrón anterior (`"(\S+)\s+(.+?)\s+HTTP/[0-9.]+"`) hacía retroceso cuadrático con una
# tira de espacios (medido: 8 KB = 0,1 s, 64 KB = 6 s de CPU por línea, con todo el servidor detenido).
_NGINX_RE = re.compile(
    r'^(?P<ip>\S+) +- +\S+ +'
    r'\[(?P<time>[^\]]*)\] +'
    r'"(?P<request>[^"]*)" +'
    r'(?P<status>\d{3}) +'
    r'(?P<bytes>\d{1,18}|-) +'
    r'"(?P<referer>[^"]*)" +'
    r'"(?P<ua>[^"]*)"'
)
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"
_MAX_METHOD_CHARS = 16


def split_request_line(request: str) -> tuple[str, str]:
    """`GET /a?b=1 HTTP/1.1` -> (`GET`, `/a?b=1`). Tolera una petición mal formada (espacios en la ruta, sin protocolo): lo que
    sobra entre el método y el protocolo es la ruta; no se descarta nada."""
    method, _, rest = request.strip().partition(" ")
    cut = rest.rfind(" HTTP/")
    if cut >= 0 and rest[cut + 6 :].replace(".", "").isdigit():
        rest = rest[:cut]
    elif rest.startswith("HTTP/") and rest[5:].replace(".", "").isdigit():
        rest = ""
    return method[:_MAX_METHOD_CHARS] or "-", rest.strip()


class NginxCombinedParser(Parser):
    def parse_line(self, raw: str) -> Optional[LogEvent]:
        m = _NGINX_RE.match(raw.strip())
        if not m:
            return None
        try:
            ts = (
                datetime.strptime(m.group("time"), _TIME_FMT)
                .astimezone(timezone.utc)
                .replace(tzinfo=None)
            )
        except (ValueError, OverflowError):  # fecha inválida o fuera de rango (año 9999 + zona horaria)
            return None

        method, full_path = split_request_line(m.group("request"))
        path, _, query = full_path.partition("?")

        referer: Optional[str] = m.group("referer") or None
        if referer == "-":
            referer = None

        raw_bytes = m.group("bytes")
        bytes_sent = int(raw_bytes) if raw_bytes != "-" else 0

        return LogEvent(
            ts=ts,
            src_ip=m.group("ip"),
            method=method,
            path=path,
            query=query,
            status=int(m.group("status")),
            user_agent=m.group("ua"),
            bytes_sent=bytes_sent,
            referer=referer,
            raw=raw,
        )
