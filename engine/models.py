from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class LogEvent:
    ts: datetime
    src_ip: str
    method: str
    path: str
    query: str
    status: int
    user_agent: str
    bytes_sent: int
    referer: Optional[str]
    raw: str


@dataclass
class Alert:
    ts: datetime
    src_ip: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    evidence: str
    raw_event: str
