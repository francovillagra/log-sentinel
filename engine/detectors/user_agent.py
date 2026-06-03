from typing import Optional

from engine.detectors.base import Detector
from engine.models import Alert, LogEvent, Severity
from engine.rules import SUSPICIOUS_UA_PATTERN


class SuspiciousUserAgentDetector(Detector):
    def inspect(self, event: LogEvent) -> Optional[Alert]:
        m = SUSPICIOUS_UA_PATTERN.search(event.user_agent)
        if not m:
            return None
        return Alert(
            ts=event.ts,
            src_ip=event.src_ip,
            rule_id="suspicious_ua",
            severity=Severity.MEDIUM,
            title="Suspicious User Agent",
            description=f"Scanner UA detected from {event.src_ip}",
            evidence=event.user_agent,
            raw_event=event.raw,
        )
