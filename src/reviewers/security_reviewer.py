from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Protocol


def review_schema() -> dict[str, Any]:
    finding = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "finding_id": {"type": "string"},
            "title": {"type": "string"},
            "cwe_id": {"type": "string"},
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
            },
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "file": {"type": "string"},
            "start_line": {"type": "integer", "minimum": 1},
            "end_line": {"type": "integer", "minimum": 1},
            "evidence": {"type": "string"},
            "reasoning_summary": {"type": "string"},
            "attack_preconditions": {
                "type": "array",
                "items": {"type": "string"},
            },
            "remediation": {"type": "string"},
            "related_symbols": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "required": [
            "finding_id", "title", "cwe_id", "severity", "confidence",
            "file", "start_line", "end_line", "evidence",
            "reasoning_summary", "attack_preconditions", "remediation",
            "related_symbols"
        ],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "packet_id": {"type": "string"},
            "verdict": {
                "type": "string",
                "enum": ["no_finding", "findings", "insufficient_context"],
            },
            "summary": {"type": "string"},
            "findings": {"type": "array", "items": finding},
            "missing_context": {
                "type": "array", "items": {"type": "string"}
            },
        },
        "required": [
            "packet_id", "verdict", "summary", "findings", "missing_context"
        ],
    }


def build_user_prompt(packet: dict[str, Any]) -> str:
    compact_packet = {
        "packet_id": packet["packet_id"],
        "batch_id": packet["batch_id"],
        "target": packet["target"],
        "context": packet["context"],
        "context_metrics": packet["context_metrics"],
    }
    return (
        "Review this bounded SAST packet. The response packet_id must exactly "
        "match the input packet_id.\n\n"
        + json.dumps(compact_packet, ensure_ascii=False, indent=2)
    )


def validate_review(review: dict[str, Any], packet_id: str) -> None:
    if review.get("packet_id") != packet_id:
        raise ValueError("Response packet_id does not match the request")
    if review.get("verdict") not in {
        "no_finding", "findings", "insufficient_context"
    }:
        raise ValueError("Invalid review verdict")
    findings = review.get("findings")
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    if review["verdict"] == "findings" and not findings:
        raise ValueError("findings verdict requires at least one finding")
    if review["verdict"] != "findings" and findings:
        raise ValueError("Non-findings verdict must have an empty findings list")
    for finding in findings:
        confidence = finding.get("confidence")
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            raise ValueError("Finding confidence must be between 0 and 1")
        start_line = finding.get("start_line")
        end_line = finding.get("end_line")
        if not isinstance(start_line, int) or not isinstance(end_line, int):
            raise ValueError("Finding lines must be integers")
        if start_line < 1 or end_line < start_line:
            raise ValueError("Finding source range is invalid")


@dataclass(frozen=True)
class ReviewResponse:
    review: dict[str, Any]
    response_id: str
    model: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    latency_seconds: float


class ReviewerClient(Protocol):
    def review(
        self, system_prompt: str, user_prompt: str, schema: dict[str, Any]
    ) -> ReviewResponse: ...


class OpenAIResponsesReviewer:
    def __init__(
        self, model: str, reasoning_effort: str, max_output_tokens: int
    ) -> None:
        from openai import OpenAI

        self.client = OpenAI()
        self.model = model
        self.reasoning_effort = reasoning_effort
        self.max_output_tokens = max_output_tokens

    def review(
        self, system_prompt: str, user_prompt: str, schema: dict[str, Any]
    ) -> ReviewResponse:
        started = time.perf_counter()
        response = self.client.responses.create(
            model=self.model,
            instructions=system_prompt,
            input=user_prompt,
            reasoning={"effort": self.reasoning_effort},
            max_output_tokens=self.max_output_tokens,
            text={
                "format": {
                    "type": "json_schema",
                    "name": "security_review",
                    "strict": True,
                    "schema": schema,
                }
            },
        )
        latency = time.perf_counter() - started
        review = json.loads(response.output_text)
        usage = response.usage
        return ReviewResponse(
            review=review,
            response_id=response.id,
            model=response.model,
            input_tokens=int(getattr(usage, "input_tokens", 0)),
            output_tokens=int(getattr(usage, "output_tokens", 0)),
            total_tokens=int(getattr(usage, "total_tokens", 0)),
            latency_seconds=latency,
        )


class GeminiInteractionsReviewer:
    def __init__(
        self, model: str, max_output_tokens: int, reasoning_effort: str
    ) -> None:
        from google import genai

        self.client = genai.Client()
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.reasoning_effort = reasoning_effort

    def review(
        self, system_prompt: str, user_prompt: str, schema: dict[str, Any]
    ) -> ReviewResponse:
        started = time.perf_counter()
        interaction = self.client.interactions.create(
            model=self.model,
            system_instruction=system_prompt,
            input=user_prompt,
            response_format={
                "type": "text",
                "mime_type": "application/json",
                "schema": schema,
            },
            generation_config={
                "max_output_tokens": self.max_output_tokens,
                "thinking_level": self.reasoning_effort,
            },
        )
        latency = time.perf_counter() - started
        review = json.loads(interaction.output_text)
        usage = interaction.usage
        return ReviewResponse(
            review=review,
            response_id=interaction.id,
            model=getattr(interaction, "model", self.model),
            input_tokens=int(getattr(usage, "total_input_tokens", 0)),
            output_tokens=int(getattr(usage, "total_output_tokens", 0)),
            total_tokens=int(getattr(usage, "total_tokens", 0)),
            latency_seconds=latency,
        )
