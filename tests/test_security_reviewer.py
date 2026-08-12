from __future__ import annotations

import unittest

from src.reviewers.security_reviewer import (
    ReviewResponse,
    build_user_prompt,
    review_schema,
    validate_review,
)
from scripts.review_security import execute_review


class SecurityReviewerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.packet = {
            "packet_id": "review-test",
            "batch_id": "batch-01",
            "target": {"symbol": "target", "code": "void target(void) {}"},
            "context": {"related_functions": []},
            "context_metrics": {"packet_estimated_tokens": 10},
        }

    def test_prompt_contains_packet_identity_and_code(self) -> None:
        prompt = build_user_prompt(self.packet)
        self.assertIn("review-test", prompt)
        self.assertIn("void target(void) {}", prompt)

    def test_schema_is_strict(self) -> None:
        schema = review_schema()
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("findings", schema["required"])
        item = schema["properties"]["findings"]["items"]
        self.assertFalse(item["additionalProperties"])

    def test_accepts_valid_no_finding_review(self) -> None:
        review = {
            "packet_id": "review-test",
            "verdict": "no_finding",
            "summary": "No supported finding.",
            "findings": [],
            "missing_context": [],
        }
        validate_review(review, "review-test")

    def test_rejects_packet_mismatch(self) -> None:
        review = {
            "packet_id": "wrong",
            "verdict": "no_finding",
            "summary": "",
            "findings": [],
            "missing_context": [],
        }
        with self.assertRaises(ValueError):
            validate_review(review, "review-test")

    def test_rejects_findings_verdict_without_findings(self) -> None:
        review = {
            "packet_id": "review-test",
            "verdict": "findings",
            "summary": "",
            "findings": [],
            "missing_context": [],
        }
        with self.assertRaises(ValueError):
            validate_review(review, "review-test")

    def test_execute_review_accepts_provider_protocol(self) -> None:
        class FakeClient:
            def review(self, system_prompt, user_prompt, schema):
                return ReviewResponse(
                    review={
                        "packet_id": "review-test",
                        "verdict": "no_finding",
                        "summary": "No supported finding.",
                        "findings": [],
                        "missing_context": [],
                    },
                    response_id="fake-response",
                    model="fake-model",
                    input_tokens=10,
                    output_tokens=5,
                    total_tokens=15,
                    latency_seconds=0.01,
                )

        config = {
            "max_retries": 0,
            "retry_base_seconds": 0,
            "prompt_version": "test-v1",
        }
        result = execute_review(FakeClient(), self.packet, config, "system")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["usage"]["total_tokens"], 15)


if __name__ == "__main__":
    unittest.main()
