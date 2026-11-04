#!/usr/bin/env python3
"""Offline, standard-library-only HTTP access log triage tool.

This is a heuristic detector. A match is not proof of exploitation or compromise.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import unquote_plus


@dataclass(frozen=True)
class RequestEvent:
    line: int
    ip: str
    timestamp: str
    method: str
    uri: str
    status: str
    user_agent: str


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    severity: str
    explanation: str
    pattern: re.Pattern
    inspect: str = "uri"


LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?:\d+|-)'
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?.*$'
)

RULES = (
    DetectionRule(
        "PATH_TRAVERSAL", "high", "Parent-directory traversal pattern in request URI",
        re.compile(r'(?:^|[/\\])\.\.(?:[/\\]|$)', re.I),
    ),
    DetectionRule(
        "SENSITIVE_FILE", "medium", "Reference to a commonly sensitive file or path",
        re.compile(r'/(?:\.env(?:[./?#]|$)|\.git/config(?:[?#]|$)|etc/passwd(?:[?#]|$)|wp-config\.php(?:[?#]|$)|\.ssh/id_rsa(?:[?#]|$))', re.I),
    ),
    DetectionRule(
        "SQLI_PATTERN", "high", "String resembling a SQL injection payload",
        re.compile(r'\bunion\s+(?:all\s+)?select\b|\b(?:sleep|benchmark)\s*\(|\b(?:or|and)\s+\d+\s*=\s*\d+\b', re.I),
    ),
    DetectionRule(
        "XSS_PATTERN", "medium", "String resembling a cross-site scripting payload",
        re.compile(r'<\s*script\b|\bonerror\s*=|\bjavascript\s*:', re.I),
    ),
    DetectionRule(
        "WEBSHELL_NAME", "medium", "Request for a filename often associated with web shells (not proof of compromise)",
        re.compile(r'(?:^|/)(?:suo5|shell|cmd|wso|b374k)\.(?:jsp|jspx|php|asp|aspx)(?:[?#]|$)', re.I),
    ),
    DetectionRule(
        "OPENAPI_DISCOVERY", "low", "Access to an API schema or documentation path; often legitimate",
        re.compile(r'/(?:openapi\.json|swagger\.json|v[23]/api-docs)(?:[?#]|$)', re.I),
    ),
    DetectionRule(
        "WORDPRESS_PROBE", "low", "Request to a WordPress-associated path; not proof WordPress is installed",
        re.compile(r'/(?:wp-login\.php|xmlrpc\.php)(?:[?#]|$)|/wp-admin(?:[/?#]|$)', re.I),
    ),
    DetectionRule(
        "SCRIPTED_CLIENT", "info", "Automated HTTP client user agent; not inherently malicious",
        re.compile(r'\b(?:curl/|python-requests/|go-http-client/|wget/)', re.I),
        inspect="user_agent",
    ),
)

CSV_FIELDS = ("line", "ip", "timestamp", "method", "status", "uri", "decoded_uri", "user_agent", "rule_id", "severity", "explanation")


def first_present(data: dict, *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return str(value)
    return ""


def parse_event(raw_line: str, line_number: int) -> RequestEvent:
    raw_line = raw_line.strip()
    if not raw_line:
        raise ValueError("blank line")

    if raw_line.startswith("{"):
        try:
            data = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSON") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON value must be an object")
        uri = first_present(data, "uri", "request_uri", "url", "path")
        request = first_present(data, "request")
        if not uri and request:
            parts = request.split()
            if len(parts) >= 2:
                uri = parts[1]
        if not uri:
            raise ValueError("JSON record has no URI")
        method = first_present(data, "method", "request_method")
        if not method and request:
            method = request.split()[0]
        return RequestEvent(
            line_number,
            first_present(data, "client_ip", "remote_addr", "source_ip", "ip") or "-",
            first_present(data, "timestamp", "time", "time_local"),
            method or "-",
            uri,
            first_present(data, "status", "status_code") or "-",
            first_present(data, "user_agent", "http_user_agent", "ua"),
        )

    match = LOG_PATTERN.match(raw_line)
    if not match:
        raise ValueError("unrecognized access log format")
    request_fields = match.group("request").split()
    if len(request_fields) < 2:
        raise ValueError("missing HTTP request target")
    return RequestEvent(
        line_number,
        match.group("ip"),
        match.group("time"),
        request_fields[0],
        request_fields[1],
        match.group("status"),
        match.group("ua") or "",
    )


def decode_uri(uri: str, rounds: int = 3) -> str:
    """Decode percent escapes (including nested escapes) up to `rounds` times."""
    output = uri
    for _ in range(rounds):
        decoded = unquote_plus(output, errors="replace")
        if decoded == output:
            break
        output = decoded
    return output


def detect(event: RequestEvent) -> list[dict[str, str | int]]:
    decoded = decode_uri(event.uri)
    findings = []
    for rule in RULES:
        value = event.user_agent if rule.inspect == "user_agent" else decoded
        if rule.pattern.search(value):
            findings.append({
                "line": event.line, "ip": event.ip, "timestamp": event.timestamp,
                "method": event.method, "status": event.status, "uri": event.uri,
                "decoded_uri": decoded, "user_agent": event.user_agent,
                "rule_id": rule.rule_id, "severity": rule.severity,
                "explanation": rule.explanation,
            })
    return findings


def csv_safe(value: str | int) -> str:
    """Prevent spreadsheet formula evaluation of attacker-controlled log fields."""
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")) and text not in ("-",):
        return "'" + text
    return text


def analyze(input_path: Path, csv_path: Path, summary_path: Path) -> dict:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    by_rule: Counter = Counter()
    by_severity: Counter = Counter()
    by_ip: Counter = Counter()
    total_lines = parsed = matched = findings_count = skipped = 0

    with input_path.open("r", encoding="utf-8-sig", errors="replace") as source, \
            csv_path.open("w", newline="", encoding="utf-8-sig") as destination:
        writer = csv.DictWriter(destination, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for number, line in enumerate(source, start=1):
            total_lines += 1
            try:
                event = parse_event(line, number)
            except ValueError as exc:
                skipped += 1
                if skipped <= 5:
                    print(f"Warning: line {number}: {exc}", file=sys.stderr)
                continue
            parsed += 1
            detections = detect(event)
            if detections:
                matched += 1
                by_ip[event.ip] += 1
            for item in detections:
                writer.writerow({key: csv_safe(item[key]) for key in CSV_FIELDS})
                findings_count += 1
                by_rule[str(item["rule_id"])] += 1
                by_severity[str(item["severity"])] += 1

    if skipped > 5:
        print(f"Warning: {skipped} total lines skipped (only first five warnings shown)", file=sys.stderr)
    summary = {
        "input_file": input_path.name,
        "total_lines": total_lines,
        "parsed_events": parsed,
        "skipped_lines": skipped,
        "matched_events": matched,
        "total_findings": findings_count,
        "by_rule": dict(sorted(by_rule.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "top_ips_by_matched_event_count": [
            {"ip": ip, "matched_events": count} for ip, count in by_ip.most_common(10)
        ],
        "disclaimer": "Heuristic log matches do not establish exploitation or compromise.",
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Offline HTTP access log threat triage (heuristic; no network access).")
    parser.add_argument("--input", required=True, type=Path, help="Apache/Nginx combined log or JSONL file")
    parser.add_argument("--output", type=Path, default=Path("results/findings.csv"), help="Findings CSV path")
    parser.add_argument("--summary", type=Path, default=Path("results/summary.json"), help="Summary JSON path")
    args = parser.parse_args(argv)
    if not args.input.is_file():
        parser.error(f"input file not found: {args.input}")
    if args.output.resolve() == args.input.resolve() or args.summary.resolve() == args.input.resolve():
        parser.error("output paths must not overwrite the input file")
    if args.output.resolve() == args.summary.resolve():
        parser.error("output and summary paths must be different")
    try:
        result = analyze(args.input, args.output, args.summary)
    except OSError as exc:
        parser.exit(1, f"I/O error: {exc}\n")
    print(f"Parsed {result['parsed_events']} events | Matched {result['matched_events']} events | "
          f"Findings {result['total_findings']} | Skipped {result['skipped_lines']} lines")
    print(f"CSV: {args.output}\nSummary: {args.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
