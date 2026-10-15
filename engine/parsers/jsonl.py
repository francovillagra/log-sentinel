import json
from datetime import datetime, timezone
from typing import Any, Optional

from engine.models import LogEvent
from engine.parsers.base import Parser
from engine.parsers.nginx import split_request_line

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S+00:00",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_ts(raw: str) -> datetime:
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=None)
        except ValueError:
            continue
    return _utcnow()


def _text(value: Any, default: str = "") -> str:
    """Un campo del JSON puede venir con cualquier tipo (número, lista, objeto): a texto o al valor por defecto, nunca una
    excepción (antes, `{"request": 123}` o un user-agent numérico devolvían 500 y el lote entero se perdía)."""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return default


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


class JsonLinesParser(Parser):
    def parse_line(self, raw: str) -> Optional[LogEvent]:
        stripped = raw.strip()
        if not stripped.startswith("{"):
            return None
        try:
            obj = json.loads(stripped)
        except (ValueError, RecursionError):  # JSON mal formado o anidado hasta desbordar la pila
            return None
        if not isinstance(obj, dict):
            return None

        ts_raw = obj.get("time") or obj.get("ts") or obj.get("timestamp")
        ts = _parse_ts(ts_raw) if isinstance(ts_raw, str) and ts_raw else _utcnow()

        method, full_path = split_request_line(_text(obj.get("request"), "GET / HTTP/1.1"))
        path, _, query = full_path.partition("?")

        referer: Optional[str] = _text(obj.get("referer") or obj.get("http_referer")) or None
        if referer == "-":
            referer = None

        return LogEvent(
            ts=ts,
            src_ip=_text(obj.get("remote_addr") or obj.get("src_ip"), "-") or "-",
            method=method,
            path=path,
            query=query,
            status=_int(obj.get("status", 0)),
            user_agent=_text(obj.get("http_user_agent") or obj.get("user_agent"), "-") or "-",
            bytes_sent=_int(obj.get("body_bytes_sent") or obj.get("bytes_sent") or 0),
            referer=referer,
            raw=raw,
        )
