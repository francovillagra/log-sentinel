import json
from datetime import datetime, timezone
from typing import Optional

from engine.models import LogEvent
from engine.parsers.base import Parser

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S+00:00",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
)


def _parse_ts(raw: str) -> datetime:
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=None)
        except ValueError:
            continue
    return datetime.utcnow()


class JsonLinesParser(Parser):
    def parse_line(self, raw: str) -> Optional[LogEvent]:
        stripped = raw.strip()
        if not stripped.startswith("{"):
            return None
        try:
            obj = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return None

        try:
            ts_raw = obj.get("time") or obj.get("ts") or obj.get("timestamp") or ""
            ts = _parse_ts(ts_raw) if ts_raw else datetime.utcnow()

            request: str = obj.get("request", "GET / HTTP/1.1")
            parts = request.split()
            method = parts[0] if parts else "GET"
            full_path = parts[1] if len(parts) > 1 else "/"
            path, _, query = full_path.partition("?")

            referer: Optional[str] = obj.get("referer") or obj.get("http_referer")
            if referer == "-":
                referer = None

            return LogEvent(
                ts=ts,
                src_ip=obj.get("remote_addr") or obj.get("src_ip") or "-",
                method=method,
                path=path,
                query=query,
                status=int(obj.get("status", 0)),
                user_agent=obj.get("http_user_agent") or obj.get("user_agent") or "-",
                bytes_sent=int(obj.get("body_bytes_sent") or obj.get("bytes_sent") or 0),
                referer=referer,
                raw=raw,
            )
        except (KeyError, ValueError, TypeError, IndexError):
            return None
