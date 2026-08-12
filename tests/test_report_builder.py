from __future__ import annotations

import unittest

from src.reporters.report_builder import build_report, findings_table


class ReportBuilderTests(unittest.TestCase):
    def test_table_escapes_pipe(self) -> None:
        item = {"disposition": "confirmed", "severity": "high", "cwe_id": "CWE-1", "target_symbol": "f", "file": "a.c", "start_line": 1, "title": "a | b"}
        self.assertIn("a \\| b", findings_table([item]))

    def test_report_contains_required_assignment_sections(self) -> None:
        finding = {"disposition": "confirmed", "severity": "high", "cwe_id": "CWE-1", "target_symbol": "f", "file": "a.c", "start_line": 1, "end_line": 1, "title": "title", "validator_confidence": 1.0, "attack_surface": "input", "rationale": "reason", "remediation": "fix"}
        data = {"findings": [finding], "review_manifest": {"request_count": 1, "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}, "validation_manifest": {"input_findings": 1}, "target": {"url": "https://example.test", "commit": "abc"}, "cppcheck": None}
        report = build_report(data)
        self.assertIn("Agent 구성도", report)
        self.assertIn("Agent skill 작성 시 주안점", report)
        self.assertIn("토큰 절약 설계와 도입 이유", report)


if __name__ == "__main__":
    unittest.main()
