import re
from datetime import datetime, timezone
from typing import Optional

from engine.models import LogEvent
from engine.parsers.base import Parser

# $remote_addr - $remote_user [$time_local] "$request" $status $bytes "$referer" "$ua"
_NGINX_RE = re.compile(
    r'^(?P<ip>\S+)\s+-\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<request>.+?)\s+HTTP/[0-9.]+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<ua>[^"]*)"'
)
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


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
        except ValueError:
            return None

        full_path = m.group("request")
        path, _, query = full_path.partition("?")

        referer: Optional[str] = m.group("referer") or None
        if referer == "-":
            referer = None

        raw_bytes = m.group("bytes")
        bytes_sent = int(raw_bytes) if raw_bytes != "-" else 0

        return LogEvent(
            ts=ts,
            src_ip=m.group("ip"),
            method=m.group("method"),
            path=path,
            query=query,
            status=int(m.group("status")),
            user_agent=m.group("ua"),
            bytes_sent=bytes_sent,
            referer=referer,
            raw=raw,
        )
