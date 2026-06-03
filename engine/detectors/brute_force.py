from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

from engine.detectors.base import Detector
from engine.models import Alert, LogEvent, Severity
from engine.rules import BRUTE_FORCE_CONFIG


class BruteForceDetector(Detector):
    """Stateful: per-IP deque of failed-auth timestamps; fires once per window."""

    def __init__(self) -> None:
        self._windows: dict[str, deque[datetime]] = defaultdict(deque)
        self._last_alert: dict[str, datetime] = {}

    def inspect(self, event: LogEvent) -> Optional[Alert]:
        cfg = BRUTE_FORCE_CONFIG
        is_auth = any(event.path.startswith(p) for p in cfg.auth_paths)
        if not is_auth or event.status not in cfg.auth_statuses:
            return None

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
            rule_id="brute_force",
            severity=Severity.HIGH,
            title="Brute Force Detected",
            description=(
                f"{len(window)} failed auth requests from {event.src_ip} "
                f"within {cfg.window_seconds}s"
            ),
            evidence=f"path={event.path} status={event.status} count={len(window)}",
            raw_event=event.raw,
        )
