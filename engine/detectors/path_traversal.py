import urllib.parse
from typing import Optional

from engine.detectors.base import Detector
from engine.models import Alert, LogEvent, Severity
from engine.rules import PATH_TRAVERSAL_PATTERN


class PathTraversalDetector(Detector):
    def inspect(self, event: LogEvent) -> Optional[Alert]:
        raw = event.path + ("?" + event.query if event.query else "")
        target = urllib.parse.unquote(raw)
        m = PATH_TRAVERSAL_PATTERN.search(target)
        if not m:
            return None
        return Alert(
            ts=event.ts,
            src_ip=event.src_ip,
            rule_id="path_traversal",
            severity=Severity.HIGH,
            title="Path Traversal Attempt",
            description=f"Path traversal pattern in request from {event.src_ip}",
            evidence=m.group().strip(),
            raw_event=event.raw,
        )
