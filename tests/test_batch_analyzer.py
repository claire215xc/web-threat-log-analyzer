"""Unit tests for batch input, aggregation, and HTML output safety."""
import csv
import json
import tempfile
import unittest
from pathlib import Path

from batch_analyzer import analyze_batch, discover_files, main, render_html


class BatchAnalyzerTests(unittest.TestCase):
    def test_discover_directory_recursive_and_deduplication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "nested"
            nested.mkdir()
            first = root / "access.log"
            second = nested / "api.jsonl"
            third = nested / "README.md"
            first.write_text("test", encoding="utf-8")
            second.write_text("test", encoding="utf-8")
            third.write_text("test", encoding="utf-8")
            result = discover_files([str(root), str(first)])
            self.assertEqual(result, sorted([first.resolve(), second.resolve()]))

    def test_discover_glob_and_missing_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "one.log").write_text("", encoding="utf-8")
            (root / "two.log").write_text("", encoding="utf-8")
            self.assertEqual(len(discover_files([str(root / "*.log")])), 2)
            with self.assertRaisesRegex(ValueError, "no files matched"):
                discover_files([str(root / "missing*.log")])

    def test_batch_aggregation_and_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "one.jsonl"
            second = root / "two.jsonl"
            first.write_text("\n".join([
                json.dumps({"ip": "192.0.2.1", "uri": "/openapi.json", "status": 200}),
                json.dumps({"ip": "192.0.2.1", "uri": "/?id=1%20UNION%20SELECT%201", "status": 403}),
                "broken-line", ""]), encoding="utf-8")
            second.write_text("\n".join([
                json.dumps({"ip": "192.0.2.1", "uri": "/wp-login.php", "status": 404}),
                json.dumps({"ip": "203.0.113.10", "uri": "/", "status": 200}), ""]), encoding="utf-8")
            folder = root / "results"
            summary = analyze_batch([first, second], csv_path=folder / "findings.csv",
                                    ip_csv_path=folder / "ips.csv",
                                    summary_path=folder / "summary.json",
                                    html_path=folder / "report.html")
            self.assertEqual(summary["input_file_count"], 2)
            self.assertEqual(summary["parsed_events"], 4)
            self.assertEqual(summary["matched_events"], 3)
            self.assertEqual(summary["total_findings"], 3)
            self.assertEqual(summary["skipped_lines"], 1)
            self.assertEqual(summary["top_ips_by_matched_event_count"][0]["matched_events"], 3)
            self.assertEqual(summary["by_rule"]["SQLI_PATTERN"], 1)
            with (folder / "findings.csv").open(encoding="utf-8-sig", newline="") as stream:
                findings = list(csv.DictReader(stream))
            self.assertEqual(len(findings), 3)
            self.assertEqual({r["source_file"] for r in findings}, {str(first), str(second)})
            with (folder / "ips.csv").open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["ip"], "192.0.2.1")
            self.assertIn("OPENAPI_DISCOVERY:1", rows[0]["rule_breakdown"])
            self.assertEqual(json.loads((folder / "summary.json").read_text())["matched_events"], 3)
            self.assertIn("192.0.2.1", (folder / "report.html").read_text())

    def test_html_escapes_untrusted_values_and_omits_raw_uri(self):
        summary = {
            "input_file_count": 1, "parsed_events": 1, "matched_events": 1,
            "total_findings": 1, "skipped_lines": 0,
            "by_rule": {"<script>alert(1)</script>": 1},
            "top_ips_by_matched_event_count": [{"ip": "<script>alert(2)</script>",
                                                 "matched_events": 1, "total_findings": 1}],
            "by_file": [{"file": "<img src=x onerror=1>.jsonl", "parsed_events": 1,
                         "matched_events": 1, "total_findings": 1, "skipped_lines": 0}],
        }
        report = render_html(summary)
        self.assertNotIn("<script>", report)
        self.assertNotIn("<img src=x", report)
        self.assertIn("&lt;script&gt;", report)
        self.assertIn("&lt;img", report)

    def test_input_output_collision_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src.log"
            src.write_text("content", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must not overwrite input"):
                analyze_batch([src], csv_path=src, summary_path=root / "other.json",
                              html_path=root / "report.html", ip_csv_path=root / "ips.csv")

    def test_cli_on_real_sample(self):
        root = Path(__file__).resolve().parent.parent
        sample = root / "samples" / "sample_access.log"
        if not sample.exists():
            self.skipTest("sample file missing from local test checkout")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            status = main(["--input", str(sample), "--output", str(output / "findings.csv"),
                           "--summary", str(output / "summary.json"),
                           "--html", str(output / "report.html"),
                           "--ip-output", str(output / "ip.csv")])
            self.assertEqual(status, 0)
            self.assertTrue((output / "report.html").exists())


if __name__ == "__main__":
    unittest.main()
