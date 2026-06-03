#!/usr/bin/env python3
"""log-sentinel CLI: detect attacks in web access logs.

Usage:
    python cli.py samples/access.log
    cat samples/access.log | python cli.py -
"""
import argparse
import os
import sys
from collections import Counter

from engine.detectors.brute_force import BruteForceDetector
from engine.detectors.injection import SqlInjectionDetector, XssDetector
from engine.detectors.path_traversal import PathTraversalDetector
from engine.detectors.rate_anomaly import RateAnomalyDetector
from engine.detectors.user_agent import SuspiciousUserAgentDetector
from engine.engine import Engine
from engine.models import Severity
from engine.parsers.jsonl import JsonLinesParser
from engine.parsers.nginx import NginxCombinedParser

_USE_COLOR = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"

_SEV_COLOR: dict[Severity, str] = {
    Severity.INFO:     "\033[36m",
    Severity.LOW:      "\033[32m",
    Severity.MEDIUM:   "\033[33m",
    Severity.HIGH:     "\033[31m",
    Severity.CRITICAL: "\033[35m",
}
_RESET = "\033[0m" if _USE_COLOR else ""
_BOLD  = "\033[1m" if _USE_COLOR else ""

_SEV_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def _color(sev: Severity, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{_SEV_COLOR[sev]}{text}{_RESET}"


def _build_engine() -> Engine:
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="log-sentinel: real-time attack detection in web logs"
    )
    parser.add_argument("logfile", help="Log file path, or - to read from stdin")
    args = parser.parse_args()

    if args.logfile == "-":
        fh = sys.stdin
    else:
        try:
            fh = open(args.logfile, encoding="utf-8", errors="replace")
        except OSError as exc:
            sys.exit(f"error: {exc}")

    engine = _build_engine()
    total = parsed = skipped = 0
    sev_counts: Counter[str] = Counter()
    ip_counts: Counter[str] = Counter()

    try:
        for raw in fh:
            raw = raw.rstrip("\n")
            if not raw.strip():
                continue
            total += 1
            event, alerts = engine.process_line(raw)
            if event is not None:
                parsed += 1
            else:
                skipped += 1
            for alert in alerts:
                tag = _color(alert.severity, f"[{alert.severity.value}]")
                print(f"{tag} {alert.rule_id} | {alert.src_ip} | {alert.evidence}")
                sev_counts[alert.severity.value] += 1
                ip_counts[alert.src_ip] += 1
    finally:
        if fh is not sys.stdin:
            fh.close()

    divider = f"{_BOLD}{'-' * 56}{_RESET}"
    print(f"\n{divider}")
    print(f"{_BOLD}SUMMARY{_RESET}")
    print(f"  Lines total  : {total}")
    print(f"  Parsed       : {parsed}")
    print(f"  Skipped      : {skipped}")
    total_alerts = sum(sev_counts.values())
    print(f"  Alerts total : {total_alerts}")

    if sev_counts:
        print(f"\n  By severity:")
        for sev in _SEV_ORDER:
            count = sev_counts.get(sev.value, 0)
            if count:
                label = _color(sev, f"{sev.value:<8}")
                print(f"    {label}  {count}")

    if ip_counts:
        print(f"\n  Top attacking IPs:")
        for ip, count in ip_counts.most_common(5):
            print(f"    {ip:<20}  {count} alert(s)")


if __name__ == "__main__":
    main()
