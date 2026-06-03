from abc import ABC, abstractmethod
from typing import Optional

from engine.models import LogEvent


class Parser(ABC):
    @abstractmethod
    def parse_line(self, raw: str) -> Optional[LogEvent]:
        ...
