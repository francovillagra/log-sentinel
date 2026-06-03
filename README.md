# log-sentinel

Blue Team SIEM-lite — Phase 1 detection engine. Python 3.11+, standard library only.

## Usage

```bash
cd log-sentinel
python cli.py samples/access.log
cat samples/access.log | python cli.py -
```

## Detectors

| rule_id         | type      | severity | description                                         |
|-----------------|-----------|----------|-----------------------------------------------------|
| brute_force     | stateful  | HIGH     | >=5 failed auth (401/403) from same IP in 60s       |
| sqli            | stateless | HIGH     | UNION SELECT, OR 1=1, ; DROP, etc. in path/query    |
| xss             | stateless | MEDIUM   | `<script>`, `onerror=`, `javascript:`, etc.         |
| path_traversal  | stateless | HIGH     | `../`, `%2e%2e`, `/etc/passwd`, `.env`, `.git/`     |
| suspicious_ua   | stateless | MEDIUM   | sqlmap, nikto, nmap, nuclei, gobuster, etc.         |
| rate_anomaly    | stateful  | MEDIUM   | >=100 requests from same IP in 10s                  |

## Configuration

All thresholds and regex patterns live in `engine/rules.py`.

## Structure

```
engine/
  models.py          LogEvent, Alert, Severity
  rules.py           All detection patterns and thresholds
  parsers/
    base.py          Parser ABC
    nginx.py         Nginx Combined Log Format
    jsonl.py         JSON Lines (auto-detected)
  detectors/
    base.py          Detector ABC
    brute_force.py   Stateful sliding-window auth detector
    injection.py     SQLi + XSS detectors
    path_traversal.py
    user_agent.py
    rate_anomaly.py  Stateful request-rate detector
  engine.py          Orchestrates parsers + detectors
cli.py               Entry point
samples/access.log   Demo log with embedded attacks
```
