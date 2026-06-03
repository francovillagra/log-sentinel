import urllib.parse
from typing import Optional

from engine.detectors.base import Detector
from engine.models import Alert, LogEvent, Severity
from engine.rules import SQLI_PATTERN, XSS_PATTERN


def _decoded_target(event: LogEvent) -> str:
    raw = event.path + ("?" + event.query if event.query else "")
    return urllib.parse.unquote(raw)


class SqlInjectionDetector(Detector):
    def inspect(self, event: LogEvent) -> Optional[Alert]:
        target = _decoded_target(event)
        m = SQLI_PATTERN.search(target)
        if not m:
            return None
        return Alert(
            ts=event.ts,
            src_ip=event.src_ip,
            rule_id="sqli",
            severity=Severity.HIGH,
            title="SQL Injection Attempt",
            description=f"SQLi pattern in request from {event.src_ip}",
            evidence=m.group().strip(),
            raw_event=event.raw,
        )


class XssDetector(Detector):
    def inspect(self, event: LogEvent) -> Optional[Alert]:
        target = _decoded_target(event)
        m = XSS_PATTERN.search(target)
        if not m:
            return None
        return Alert(
            ts=event.ts,
            src_ip=event.src_ip,
            rule_id="xss",
            severity=Severity.MEDIUM,
            title="XSS Attempt",
            description=f"XSS pattern in request from {event.src_ip}",
            evidence=m.group().strip(),
            raw_event=event.raw,
        )
