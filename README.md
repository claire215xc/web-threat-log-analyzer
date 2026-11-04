# Web Threat Log Analyzer

A lightweight **offline** HTTP access-log triage tool written in Python. It uses **only the Python standard library** and supports common Apache/Nginx combined access logs and newline-delimited JSON (JSONL) records.

**Status:** v0.1.0 released; v0.2.0 enhancements in development. This is an initial public prototype. Detection is heuristic, not a vulnerability scanner or an incident-confirmation system.

## Features

- Apache/Nginx combined access-log or JSONL input (one event per line)
- Repeated URL decoding up to three passes for common percent-encoded payloads
- Readable rule IDs for patterns associated with path traversal, sensitive files, SQL injection, XSS, suspicious web-shell filenames, OpenAPI/Swagger discovery, WordPress paths, and automated clients
- CSV findings (UTF-8 with BOM for spreadsheet compatibility) and JSON summary
- Offline processing: **no external API, network traffic, or third-party packages**
- Unit tests and synthetic sample logs
- Batch mode for recursive folders, multiple files and glob patterns
- Batch IP-level CSV and self-contained HTML summary

## Requirements

Python 3.9 or newer. No packages to install.

## Quick start

```bash
python web_log_analyzer.py --input samples/sample_access.log
python web_log_analyzer.py --input samples/sample_jsonl.jsonl --output results/jsonl_findings.csv --summary results/jsonl_summary.json
python -m unittest discover -s tests -v
```

Windows users can use `py` instead of `python` if necessary.

Results are written to `results/findings.csv` and `results/summary.json` by default.

### Supported JSONL fields

Each line must contain a JSON object with at least one of `uri`, `request_uri`, `url`, `path`, or an HTTP `request` line. Optional fields:

- Client: `client_ip`, `remote_addr`, `source_ip`, `ip`
- Method: `method`, `request_method`
- HTTP status: `status`, `status_code`
- User agent: `user_agent`, `http_user_agent`, `ua`
- Timestamp: `timestamp`, `time`, `time_local`

Other JSON field layouts and multiline JSON are not supported in v0.1.0. Request bodies, TLS encryption, PCAP, and compressed log input are outside current scope.

## Batch analysis (proposed v0.2.0)

The original single-file command remains available. For a folder of logs, run:

```bash
python batch_analyzer.py --input samples/
python batch_analyzer.py --input samples/sample_access.log samples/sample_jsonl.jsonl
python batch_analyzer.py --input "samples/*.log"
```

Directories are scanned **recursively** for `.log`, `.jsonl`, and `.txt` files. Explicitly named files can use other extensions. Overlapping inputs are deduplicated. Batch input supports the same Apache/Nginx combined and one-JSON-object-per-line formats as the original analyzer.

By default, four local files are written to the Git-ignored `results/` directory:

| Path | Contents |
| --- | --- |
| `results/batch_findings.csv` | One row per rule match, including source file, request URI, rule ID and severity |
| `results/ip_summary.csv` | Every matched client IP with event counts and per-rule findings |
| `results/batch_summary.json` | Input-level counts, rule counts, severity counts and top 20 IPs |
| `results/report.html` | Standalone HTML overview of top IPs, rules, and file coverage |

**Interpretation:** A *matched event* is a request with one or more detection rules. *Findings* count rule matches, so one event may have multiple findings. Counts do not establish attack success or compromise.

**Privacy:** The HTML report excludes raw request URIs and user agents, and escapes visible log-derived values. However, IP addresses and source filenames still appear in HTML. Detailed CSV includes raw URIs and can contain sensitive information. Keep all generated outputs private unless separately reviewed and sanitized. No input is uploaded by the program.

Run all tests with:

```bash
python -m unittest discover -s tests -v
```

## Rules and interpretation

| Rule | Severity | Interpretation |
| --- | --- | --- |
| `PATH_TRAVERSAL` | high | Traversal-like URI pattern |
| `SENSITIVE_FILE` | medium | Request referencing a commonly sensitive path |
| `SQLI_PATTERN` | high | Common SQLi-like string in URI |
| `XSS_PATTERN` | medium | Common XSS-like string in URI |
| `WEBSHELL_NAME` | medium | Suspicious filename; does **not** prove a web shell exists |
| `OPENAPI_DISCOVERY` | low | API documentation path access; may be entirely normal |
| `WORDPRESS_PROBE` | low | WordPress-associated path request; does **not** establish WordPress use |
| `SCRIPTED_CLIENT` | info | `curl`, `wget`, etc.; does **not** by itself imply malicious intent |

Severity represents **triage priority**, not demonstrated impact or exploitation. Status 200 does not establish a successful exploit, and 404 does not exclude an attempted attack. Review context (traffic volume, authorization, asset role, application logs, other controls) before taking action.

## Privacy and security

- All sample IPs are reserved documentation addresses (RFC 5737); sample logs are synthetic.
- Do not commit real production logs, company IPs, credentials, customer information, incident details, or confidential signatures.
- Output CSV includes the original request URI and user agent and **can contain sensitive data**. The `results/` folder is ignored by Git, but ensure you have permission before processing real logs.
- CSV values are protected against spreadsheet formula injection when opening findings in spreadsheet software.
- The tool is defensive and non-intrusive: it does not send requests to external targets.

## Limitations and roadmap

Current detections are string-pattern heuristics; they can produce false positives and miss attacks. No traffic reputation, baselining, HTTP body inspection, or application-specific parsing is provided. Future versions may add configurable rules, support for additional log formats, context-aware correlation, and HTML reporting.

## Contributing

Issues and pull requests for bug fixes, test cases, and new defensive detection rules are welcome. Please use only synthetic or properly anonymized data. Do not post live secrets or production exploit details.

## License

MIT — see [LICENSE](LICENSE).
