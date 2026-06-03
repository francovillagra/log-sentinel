from abc import ABC, abstractmethod
from typing import Optional

from engine.models import Alert, LogEvent


class Detector(ABC):
    @abstractmethod
    def inspect(self, event: LogEvent) -> Optional[Alert]:
        ...
