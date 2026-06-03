import re
from dataclasses import dataclass, field


@dataclass
class BruteForceConfig:
    auth_paths: tuple[str, ...] = ("/login", "/signin", "/auth")
    auth_statuses: frozenset[int] = field(default_factory=lambda: frozenset({401, 403}))
    threshold: int = 5
    window_seconds: int = 60


@dataclass
class RateAnomalyConfig:
    threshold: int = 100
    window_seconds: int = 10


SQLI_PATTERN = re.compile(
    r"""
    union\s+select |
    \bor\s+1\s*=\s*1\b |
    '\s*or\s+' |
    --\s*(?:$|\s) |
    ;\s*drop\s+table |
    ;\s*delete\s+from |
    xp_cmdshell |
    \bcast\s*\( |
    \bconvert\s*\( |
    \bexec\s*\( |
    waitfor\s+delay
    """,
    re.IGNORECASE | re.VERBOSE,
)

XSS_PATTERN = re.compile(
    r"""
    <script |
    onerror\s*= |
    javascript: |
    <img[^>]*onerror |
    <svg[^>]*onload |
    on(?:load|click|mouseover|focus|blur)\s*= |
    \beval\s*\( |
    document\.cookie |
    alert\s*\(
    """,
    re.IGNORECASE | re.VERBOSE,
)

PATH_TRAVERSAL_PATTERN = re.compile(
    r"""
    \.\./ |
    \.\.%2f |
    %2e%2e/ |
    %2e%2e%2f |
    \.\.%5c |
    %2e%2e%5c |
    /etc/passwd |
    /etc/shadow |
    /etc/hosts |
    \.env(?:/|$) |
    \.git/ |
    /proc/self |
    /windows/system32
    """,
    re.IGNORECASE | re.VERBOSE,
)

SUSPICIOUS_UA_PATTERN = re.compile(
    r"sqlmap|nikto|nmap|nuclei|gobuster|dirbuster|masscan|acunetix|zgrab|wfuzz|burpsuite|metasploit|openvas",
    re.IGNORECASE,
)

BRUTE_FORCE_CONFIG = BruteForceConfig()
RATE_ANOMALY_CONFIG = RateAnomalyConfig()
