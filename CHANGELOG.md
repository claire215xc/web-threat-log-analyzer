# Changelog

## Unreleased (planned v0.2.0)

- Add `batch_analyzer.py` for recursive analysis of multiple access-log and JSONL files.
- Add per-IP matched-event counts and per-rule findings CSV output.
- Add self-contained HTML summary with output escaping and no raw request URIs.
- Add batch unit tests and continuous integration checks.
- Keep the original single-file CLI compatible with v0.1.0.

## v0.1.0

- Initial offline log analysis prototype with eight heuristic detection rules.
- CSV and JSON outputs, example logs and unit tests.
