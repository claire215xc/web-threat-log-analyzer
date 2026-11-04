#!/usr/bin/env python3
"""Analyze several HTTP access logs and produce aggregate, offline reports.

Run: python batch_analyzer.py --input samples/
This module extends, but does not change, the original single-file analyzer.
"""

from __future__ import annotations

import argparse
import csv
import glob
import html
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Sequence

from web_log_analyzer import CSV_FIELDS, csv_safe, detect, parse_event

LOG_SUFFIXES = frozenset({".log", ".jsonl", ".txt"})
FINDING_FIELDS = ("source_file",) + CSV_FIELDS
IP_FIELDS = ("ip", "matched_events", "total_findings", "rule_breakdown")


def discover_files(inputs: Sequence[str]) -> list[Path]:
    """Expand explicitly supplied files, recursive folders and glob expressions.

    Duplicate paths (including overlapping directory/glob inputs) are analyzed once.
    Directory traversal only includes common text-log extensions; explicit files
    may have any extension.
    """
    found: dict[Path, Path] = {}
    for value in inputs:
        candidates = [Path(name) for name in glob.glob(value, recursive=True)]
        if not candidates:
            raise ValueError(f"no files matched input: {value}")
        matched = 0
        for candidate in candidates:
            if candidate.is_dir():
                files = (p for p in candidate.rglob("*") if p.is_file() and p.suffix.lower() in LOG_SUFFIXES)
            elif candidate.is_file():
                files = (candidate,)
            else:
                continue
            for path in files:
                found[path.resolve()] = path.resolve()
                matched += 1
        if not matched:
            raise ValueError(f"no supported log files found in: {value}")
    return sorted(found.values(), key=lambda p: str(p))


def _table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    th = "".join(f"<th scope=\"col\">{html.escape(str(cell))}</th>" for cell in headers)
    body = "\n".join(
        "<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    if not body:
        body = f'<tr><td colspan="{len(headers)}">No findings</td></tr>'
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def render_html(summary: dict) -> str:
    """Render a self-contained, escaped HTML summary, without raw request URIs."""
    rules = _table(("Rule", "Findings"), sorted(summary["by_rule"].items(), key=lambda x: (-x[1], x[0])))
    ips = _table(
        ("Client IP", "Matched events", "Findings"),
        [(item["ip"], item["matched_events"], item["total_findings"])
         for item in summary["top_ips_by_matched_event_count"]],
    )
    files = _table(
        ("Input file", "Parsed", "Matched", "Findings", "Skipped"),
        [(item["file"], item["parsed_events"], item["matched_events"],
          item["total_findings"], item["skipped_lines"]) for item in summary["by_file"]],
    )
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Web Threat Log Analyzer — Batch Report</title>
  <style>
    :root {{ color-scheme: light; font-family: system-ui, sans-serif; }}
    body {{ max-width: 1050px; margin: 2rem auto; padding: 0 1rem; color: #1f2937; }}
    .metrics {{ display: flex; flex-wrap: wrap; gap: 1rem; margin: 1.5rem 0; }}
    .metric {{ border: 1px solid #d1d5db; border-radius: .5rem; padding: 1rem; min-width: 145px; }}
    .metric strong {{ display: block; font-size: 1.6rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
    th, td {{ border-bottom: 1px solid #e5e7eb; padding: .65rem; text-align: left; overflow-wrap: anywhere; }}
    th {{ background: #f3f4f6; }}
    .notice {{ border-left: 4px solid #64748b; padding: .5rem 1rem; background: #f8fafc; }}
  </style>
</head>
<body>
  <h1>Web Threat Log Analyzer</h1>
  <p>Offline batch triage report</p>
  <div class="notice">Heuristic detections are not proof of compromise. Review application context and authorization. The report intentionally excludes raw URIs and user agents.</div>
  <div class="metrics">
    <div class="metric"><strong>{summary['input_file_count']}</strong>Input files</div>
    <div class="metric"><strong>{summary['parsed_events']}</strong>Parsed events</div>
    <div class="metric"><strong>{summary['matched_events']}</strong>Matched events</div>
    <div class="metric"><strong>{summary['total_findings']}</strong>Rule findings</div>
    <div class="metric"><strong>{summary['skipped_lines']}</strong>Skipped lines</div>
  </div>
  <h2>Findings by rule</h2>
  {rules}
  <h2>Top client IPs (by matched events)</h2>
  {ips}
  <p>All IPs and their per-rule counts are included in the separate IP CSV.</p>
  <h2>Input file coverage</h2>
  {files}
  <p>All data was processed locally; no requests were sent to external services.</p>
</body>
</html>
'''


def analyze_batch(files: Sequence[Path], *, csv_path: Path, summary_path: Path,
                  html_path: Path, ip_csv_path: Path) -> dict:
    """Stream inputs once, writing detailed findings and aggregate outputs."""
    if not files:
        raise ValueError("no input files")
    outputs = (csv_path, summary_path, html_path, ip_csv_path)
    resolved_outputs = [path.resolve() for path in outputs]
    if len(set(resolved_outputs)) != len(resolved_outputs):
        raise ValueError("output paths must all be distinct")
    if set(resolved_outputs).intersection(path.resolve() for path in files):
        raise ValueError("output paths must not overwrite input files")

    by_rule: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    by_ip_events: Counter[str] = Counter()
    by_ip_findings: Counter[str] = Counter()
    by_ip_rule: dict[str, Counter[str]] = defaultdict(Counter)
    by_file: list[dict] = []
    parsed = matched = findings_count = skipped = total_lines = 0

    for path in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)

    with csv_path.open("w", newline="", encoding="utf-8-sig") as destination:
        writer = csv.DictWriter(destination, fieldnames=FINDING_FIELDS)
        writer.writeheader()
        for path in files:
            file_stats = {"file": str(path), "total_lines": 0, "parsed_events": 0,
                          "matched_events": 0, "total_findings": 0, "skipped_lines": 0}
            with path.open("r", encoding="utf-8-sig", errors="replace") as source:
                for number, line in enumerate(source, 1):
                    file_stats["total_lines"] += 1
                    total_lines += 1
                    try:
                        event = parse_event(line, number)
                    except ValueError as exc:
                        file_stats["skipped_lines"] += 1
                        skipped += 1
                        if skipped <= 5:
                            print(f"Warning: {path.name}:{number}: {exc}", file=sys.stderr)
                        continue
                    parsed += 1
                    file_stats["parsed_events"] += 1
                    findings = detect(event)
                    if findings:
                        matched += 1
                        file_stats["matched_events"] += 1
                        by_ip_events[event.ip] += 1
                    for finding in findings:
                        writer.writerow({"source_file": csv_safe(str(path)),
                                         **{field: csv_safe(finding[field]) for field in CSV_FIELDS}})
                        rule = str(finding["rule_id"])
                        by_rule[rule] += 1
                        by_severity[str(finding["severity"])] += 1
                        by_ip_findings[event.ip] += 1
                        by_ip_rule[event.ip][rule] += 1
                        findings_count += 1
                        file_stats["total_findings"] += 1
            by_file.append(file_stats)

    summary = {
        "input_file_count": len(files),
        "total_lines": total_lines,
        "parsed_events": parsed,
        "matched_events": matched,
        "total_findings": findings_count,
        "skipped_lines": skipped,
        "by_rule": dict(sorted(by_rule.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "by_file": by_file,
        "top_ips_by_matched_event_count": [
            {"ip": ip, "matched_events": count, "total_findings": by_ip_findings[ip]}
            for ip, count in sorted(by_ip_events.items(), key=lambda p: (-p[1], p[0]))[:20]
        ],
        "disclaimer": "Heuristic matches do not establish exploitation or compromise.",
    }
    with ip_csv_path.open("w", newline="", encoding="utf-8-sig") as dest:
        writer = csv.DictWriter(dest, fieldnames=IP_FIELDS)
        writer.writeheader()
        for ip, count in sorted(by_ip_events.items(), key=lambda p: (-p[1], p[0])):
            breakdown = "; ".join(f"{rule}:{value}" for rule, value in sorted(by_ip_rule[ip].items()))
            writer.writerow({"ip": csv_safe(ip), "matched_events": count,
                             "total_findings": by_ip_findings[ip], "rule_breakdown": csv_safe(breakdown)})
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    html_path.write_text(render_html(summary), encoding="utf-8")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline batch HTTP access-log triage (no network access)")
    parser.add_argument("--input", nargs="+", required=True,
                        help="One or more log files, directories, or glob patterns")
    parser.add_argument("--output", type=Path, default=Path("results/batch_findings.csv"))
    parser.add_argument("--summary", type=Path, default=Path("results/batch_summary.json"))
    parser.add_argument("--html", type=Path, default=Path("results/report.html"))
    parser.add_argument("--ip-output", type=Path, default=Path("results/ip_summary.csv"))
    args = parser.parse_args(argv)
    try:
        files = discover_files(args.input)
        summary = analyze_batch(files, csv_path=args.output, summary_path=args.summary,
                                html_path=args.html, ip_csv_path=args.ip_output)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Error: {exc}\n")
    print(f"Files {summary['input_file_count']} | Parsed {summary['parsed_events']} | "
          f"Matched {summary['matched_events']} | Findings {summary['total_findings']} | "
          f"Skipped {summary['skipped_lines']}")
    print(f"Findings: {args.output}\nIP summary: {args.ip_output}\n"
          f"JSON: {args.summary}\nHTML: {args.html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
