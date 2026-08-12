from __future__ import annotations

import json
import unittest
from pathlib import Path

from src.analyzers.candidate_finder import CandidateFinder


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class CandidateFinderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        config = json.loads(
            (PROJECT_ROOT / "config" / "risky-apis.json").read_text(
                encoding="utf-8"
            )
        )
        cls.finder = CandidateFinder(config)

    @staticmethod
    def chunk(code: str, **overrides: object) -> dict[str, object]:
        result: dict[str, object] = {
            "chunk_id": "test-chunk",
            "relative_path": "test.c",
            "symbol": "test",
            "start_line": 10,
            "end_line": 12,
            "estimated_tokens": 100,
            "has_parse_error": False,
            "code": code,
        }
        result.update(overrides)
        return result

    def test_detects_api_and_preserves_absolute_line(self) -> None:
        result = self.finder.analyze(
            self.chunk("void test(void) {\n  memcpy(a, b, n);\n}")
        )
        self.assertEqual(result["risky_api_count"], 1)
        self.assertEqual(result["risky_apis"], ["memcpy"])
        self.assertEqual(result["api_occurrences"][0]["line"], 11)

    def test_does_not_match_longer_identifier(self) -> None:
        result = self.finder.analyze(
            self.chunk("void test(void) { my_memcpy_helper(); }")
        )
        self.assertEqual(result["risky_api_count"], 0)
        self.assertEqual(result["priority_score"], 0)
        self.assertEqual(result["priority"], "low")

    def test_counts_repeated_occurrences(self) -> None:
        result = self.finder.analyze(
            self.chunk("malloc(1);\nmalloc(2);")
        )
        self.assertEqual(result["risky_api_count"], 2)
        self.assertEqual(result["risky_api_counts"], {"malloc": 2})
        self.assertEqual(result["priority_score"], 2)

    def test_applies_parse_and_large_chunk_bonuses(self) -> None:
        result = self.finder.analyze(
            self.chunk(
                "void test(void) {}",
                estimated_tokens=2001,
                has_parse_error=True,
            )
        )
        self.assertEqual(result["priority_score"], 3)
        self.assertEqual(result["priority"], "low")

    def test_priority_boundaries(self) -> None:
        medium = self.finder.analyze(self.chunk("system(cmd);"))
        high = self.finder.analyze(
            self.chunk("system(a);\nsystem(b);")
        )
        self.assertEqual(medium["priority"], "medium")
        self.assertEqual(high["priority"], "high")


if __name__ == "__main__":
    unittest.main()
