from typing import Optional

from engine.detectors.base import Detector
from engine.models import Alert, LogEvent
from engine.parsers.base import Parser


class Engine:
    def __init__(self, parsers: list[Parser], detectors: list[Detector]) -> None:
        self._parsers = parsers
        self._detectors = detectors

    def process_line(self, raw: str) -> tuple[Optional[LogEvent], list[Alert]]:
        event = self._parse(raw)
        if event is None:
            return None, []
        alerts: list[Alert] = []
        for detector in self._detectors:
            alert = detector.inspect(event)
            if alert is not None:
                alerts.append(alert)
        return event, alerts

    def _parse(self, raw: str) -> Optional[LogEvent]:
        for parser in self._parsers:
            result = parser.parse_line(raw)
            if result is not None:
                return result
        return None
