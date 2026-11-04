"""Run with: python -m unittest discover -s tests -v"""
import csv
import json
import tempfile
import unittest
from pathlib import Path

from web_log_analyzer import analyze, csv_safe, decode_uri, detect, parse_event


class AnalyzerTests(unittest.TestCase):
    def test_parse_combined(self):
        raw = '192.0.2.1 - - [04/Nov/2026:10:00:00 +0900] "GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        event = parse_event(raw, 12)
        self.assertEqual((event.ip, event.uri, event.status, event.line), ("192.0.2.1", "/", "200", 12))

    def test_parse_jsonl(self):
        event = parse_event('{"client_ip":"192.0.2.7","request":"GET /openapi.json HTTP/1.1","status":200}', 1)
        self.assertEqual(event.uri, "/openapi.json")
        self.assertEqual(event.method, "GET")

    def test_nested_percent_decoding(self):
        self.assertEqual(decode_uri('/%252e%252e%252fetc%252fpasswd'), '/../etc/passwd')

    def test_traversal_and_sensitive_file(self):
        event = parse_event('{"uri":"/%252e%252e%252fetc%252fpasswd","ip":"192.0.2.1"}', 1)
        rules = {x["rule_id"] for x in detect(event)}
        self.assertIn("PATH_TRAVERSAL", rules)
        self.assertIn("SENSITIVE_FILE", rules)

    def test_sqli_and_xss(self):
        for uri, rule in (("/?id=1%20union%20select%201", "SQLI_PATTERN"),
                          ("/?q=%3Cscript%3Ealert(1)%3C/script%3E", "XSS_PATTERN")):
            with self.subTest(rule=rule):
                event = parse_event(json.dumps({"uri": uri}), 1)
                self.assertIn(rule, {x["rule_id"] for x in detect(event)})

    def test_wordpress_path_is_only_a_probe(self):
        event = parse_event('{"uri":"/wp-login.php"}', 1)
        findings = detect(event)
        self.assertEqual([x["rule_id"] for x in findings], ["WORDPRESS_PROBE"])
        self.assertEqual(findings[0]["severity"], "low")

    def test_benign(self):
        event = parse_event('{"uri":"/","user_agent":"Mozilla/5.0"}', 1)
        self.assertEqual(detect(event), [])

    def test_csv_formula_sanitization(self):
        self.assertEqual(csv_safe('=1+1'), "'=1+1")
        self.assertEqual(csv_safe(' @SUM(1,1)'), "' @SUM(1,1)")

    def test_end_to_end_with_skipped_line(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            src = root / "input.jsonl"
            src.write_text('{"ip":"192.0.2.1","uri":"/openapi.json","status":200}\nnot-a-log\n', encoding="utf-8")
            output = root / "findings.csv"
            summary = root / "summary.json"
            result = analyze(src, output, summary)
            self.assertEqual(result["parsed_events"], 1)
            self.assertEqual(result["skipped_lines"], 1)
            self.assertEqual(result["matched_events"], 1)
            self.assertEqual(result["by_rule"]["OPENAPI_DISCOVERY"], 1)
            with output.open(encoding="utf-8-sig", newline="") as stream:
                self.assertEqual(len(list(csv.DictReader(stream))), 1)
            self.assertEqual(json.loads(summary.read_text(encoding="utf-8"))["total_findings"], 1)


if __name__ == "__main__":
    unittest.main()
