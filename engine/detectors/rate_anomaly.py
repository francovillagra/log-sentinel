from typing import Optional

from engine.detectors.base import Detector
from engine.models import Alert, LogEvent, Severity
from engine.rules import RATE_ANOMALY_CONFIG, RateAnomalyConfig
from engine.windows import SlidingThreshold


class RateAnomalyDetector(Detector):
    """Con estado: ventana deslizante de todas las peticiones por IP. La memoria está acotada (engine/windows.py)."""

    def __init__(self, config: RateAnomalyConfig = RATE_ANOMALY_CONFIG) -> None:
        self._cfg = config
        self._tracker = SlidingThreshold(config.threshold, config.window_seconds, config.max_tracked_ips)

    def inspect(self, event: LogEvent) -> Optional[Alert]:
        cfg = self._cfg
        count = self._tracker.hit(event.src_ip, event.ts)
        if count is None:
            return None
        return Alert(
            ts=event.ts,
            src_ip=event.src_ip,
            rule_id="rate_anomaly",
            severity=Severity.MEDIUM,
            title="Rate Anomaly",
            description=f"{count} requests from {event.src_ip} within {cfg.window_seconds}s",
            evidence=f"count={count} window={cfg.window_seconds}s",
            raw_event=event.raw,
        )
