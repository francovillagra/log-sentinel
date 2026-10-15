from typing import Optional

from engine.detectors.base import Detector
from engine.models import Alert, LogEvent, Severity
from engine.rules import BRUTE_FORCE_CONFIG, BruteForceConfig
from engine.windows import SlidingThreshold


class BruteForceDetector(Detector):
    """Con estado: marcas de tiempo de los fallos de autenticación por IP; avisa una vez por ventana.
    La memoria está acotada (engine/windows.py)."""

    def __init__(self, config: BruteForceConfig = BRUTE_FORCE_CONFIG) -> None:
        self._cfg = config
        self._tracker = SlidingThreshold(config.threshold, config.window_seconds, config.max_tracked_ips)

    def inspect(self, event: LogEvent) -> Optional[Alert]:
        cfg = self._cfg
        if event.status not in cfg.auth_statuses or not cfg.auth_path_pattern.search(event.target.path):
            return None

        count = self._tracker.hit(event.src_ip, event.ts)
        if count is None:
            return None
        return Alert(
            ts=event.ts,
            src_ip=event.src_ip,
            rule_id="brute_force",
            severity=Severity.HIGH,
            title="Brute Force Detected",
            description=f"{count} failed auth requests from {event.src_ip} within {cfg.window_seconds}s",
            evidence=f"path={event.path} status={event.status} count={count}",
            raw_event=event.raw,
        )
