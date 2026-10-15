from engine.detectors.brute_force import BruteForceDetector
from engine.detectors.injection import SqlInjectionDetector, XssDetector
from engine.detectors.path_traversal import PathTraversalDetector
from engine.detectors.rate_anomaly import RateAnomalyDetector
from engine.detectors.user_agent import SuspiciousUserAgentDetector
from engine.engine import Engine
from engine.parsers.jsonl import JsonLinesParser
from engine.parsers.nginx import NginxCombinedParser

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64)"


def new_engine() -> Engine:
    return Engine(
        parsers=[JsonLinesParser(), NginxCombinedParser()],
        detectors=[
            BruteForceDetector(),
            SqlInjectionDetector(),
            XssDetector(),
            PathTraversalDetector(),
            SuspiciousUserAgentDetector(),
            RateAnomalyDetector(),
        ],
    )


def nginx_line(target: str = "/", status: int = 200, ua: str = DEFAULT_UA, ip: str = "203.0.113.5",
               method: str = "GET", time: str = "01/Jan/2026:12:00:00 +0000", proto: str = "HTTP/1.1") -> str:
    request = f"{method} {target} {proto}".strip()
    return f'{ip} - - [{time}] "{request}" {status} 512 "-" "{ua}"'
