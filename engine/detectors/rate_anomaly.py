from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

from engine.detectors.base import Detector
from engine.models import Alert, LogEvent, Severity
from engine.rules import RATE_ANOMALY_CONFIG


class RateAnomalyDetector(Detector):
    """Stateful: per-IP sliding window of all request timestamps."""

    def __init__(self) -> None:
        self._windows: dict[str, deque[datetime]] = defaultdict(deque)
        self._last_alert: dict[str, datetime] = {}

    def inspect(self, event: LogEvent) -> Optional[Alert]:
        cfg = RATE_ANOMALY_CONFIG
        window = self._windows[event.src_ip]
        cutoff = event.ts - timedelta(seconds=cfg.window_seconds)
        while window and window[0] < cutoff:
            window.popleft()
        window.append(event.ts)

        if len(window) < cfg.threshold:
            return None

        last = self._last_alert.get(event.src_ip)
        if last is not None and (event.ts - last).total_seconds() < cfg.window_seconds:
            return None

        self._last_alert[event.src_ip] = event.ts
        return Alert(
            ts=event.ts,
            src_ip=event.src_ip,
            rule_id="rate_anomaly",
            severity=Severity.MEDIUM,
            title="Rate Anomaly",
            description=(
                f"{len(window)} requests from {event.src_ip} "
                f"within {cfg.window_seconds}s"
            ),
            evidence=f"count={len(window)} window={cfg.window_seconds}s",
            raw_event=event.raw,
        )
