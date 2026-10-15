import logging
from collections import Counter
from typing import Optional

from engine.detectors.base import Detector
from engine.models import Alert, LogEvent
from engine.parsers.base import Parser
from engine.rules import MAX_LINE_CHARS

log = logging.getLogger(__name__)

# Para que un detector que falla en cada línea no llene el log: se registran los primeros errores y después uno de cada mil.
_LOG_FIRST_ERRORS = 10
_LOG_EVERY = 1000


class Engine:
    """Parsea cada línea y la pasa por los detectores. Una línea nunca debe tumbar el proceso: un fallo de un parser o de un
    detector se cuenta (`stats`) y se sigue con el resto."""

    def __init__(self, parsers: list[Parser], detectors: list[Detector], max_line_chars: int = MAX_LINE_CHARS) -> None:
        self._parsers = parsers
        self._detectors = detectors
        self._max_line_chars = max_line_chars
        self.stats: Counter[str] = Counter()

    def process_line(self, raw: str) -> tuple[Optional[LogEvent], list[Alert]]:
        if len(raw) > self._max_line_chars:
            # No es una línea de un servidor web (ver MAX_LINE_CHARS): se omite sin gastar CPU y queda contada.
            self.stats["truncated"] += 1
            self.stats["skipped"] += 1
            return None, []
        event = self._parse(raw)
        if event is None:
            self.stats["skipped"] += 1
            return None, []
        self.stats["parsed"] += 1
        alerts: list[Alert] = []
        for detector in self._detectors:
            try:
                alert = detector.inspect(event)
            except Exception:  # noqa: BLE001 — un detector roto no puede dejar ciego al resto
                self._note_error("detector_errors", type(detector).__name__)
                continue
            if alert is not None:
                alerts.append(alert)
        return event, alerts

    def _parse(self, raw: str) -> Optional[LogEvent]:
        for parser in self._parsers:
            try:
                result = parser.parse_line(raw)
            except Exception:  # noqa: BLE001
                self._note_error("parser_errors", type(parser).__name__)
                continue
            if result is not None:
                return result
        return None

    def _note_error(self, counter: str, who: str) -> None:
        self.stats[counter] += 1
        n = self.stats[counter]
        if n <= _LOG_FIRST_ERRORS or n % _LOG_EVERY == 0:
            log.exception("%s: %s falló (%d en total); se omite esa línea para ese componente", counter, who, n)
