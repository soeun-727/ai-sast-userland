from __future__ import annotations

import unittest

from src.analyzers.context_builder import ContextBuilder, extract_calls


class ContextBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = ContextBuilder(
            {
                "selected_priorities": ["high", "medium"],
                "max_packet_estimated_tokens": 100,
                "max_related_functions": 2,
                "max_include_directives": 10,
            }
        )

    @staticmethod
    def record(
        symbol: str,
        code: str,
        tokens: int,
        priority: str = "high",
        risky_count: int = 1,
    ) -> dict[str, object]:
        return {
            "chunk_id": f"chunk-{symbol}",
            "relative_path": "test.c",
            "language": "c",
            "symbol": symbol,
            "start_line": 1,
            "end_line": 3,
            "estimated_tokens": tokens,
            "has_parse_error": False,
            "risky_apis": ["memcpy"] if risky_count else [],
            "risky_api_count": risky_count,
            "priority": priority,
            "code": code,
        }

    def test_extracts_unique_function_calls(self) -> None:
        calls = extract_calls(
            "void target(void) { helper(); obj->run(); helper(); }",
            "c",
        )
        self.assertEqual(calls, ["helper", "run"])

    def test_selects_only_configured_priorities_with_risk(self) -> None:
        self.assertTrue(self.builder.should_build(self.record("a", "", 1)))
        self.assertFalse(
            self.builder.should_build(
                self.record("a", "", 1, priority="low")
            )
        )
        self.assertFalse(
            self.builder.should_build(
                self.record("a", "", 1, risky_count=0)
            )
        )

    def test_adds_local_dependency_within_budget(self) -> None:
        target = self.record("target", "void target(void) { helper(); }", 60)
        helper = self.record("helper", "void helper(void) {}", 30)
        packet = self.builder.build(target, [target, helper], ["<stdio.h>"])
        self.assertEqual(
            packet["context_metrics"]["packet_estimated_tokens"],
            90,
        )
        self.assertEqual(
            packet["context"]["related_functions"][0]["symbol"],
            "helper",
        )

    def test_omits_dependency_that_exceeds_budget(self) -> None:
        target = self.record("target", "void target(void) { helper(); }", 80)
        helper = self.record("helper", "void helper(void) {}", 30)
        packet = self.builder.build(target, [target, helper], [])
        self.assertEqual(packet["context"]["related_functions"], [])
        self.assertEqual(packet["context"]["omitted_local_calls"], ["helper"])


if __name__ == "__main__":
    unittest.main()
