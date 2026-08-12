from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.reviewers.security_reviewer import (
    GeminiInteractionsReviewer,
    OpenAIResponsesReviewer,
    ReviewerClient,
    build_user_prompt,
    review_schema,
    validate_review,
)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as source:
        return [json.loads(line) for line in source if line.strip()]


def write_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_packets(context_root: Path) -> list[tuple[str, dict[str, Any]]]:
    packets: list[tuple[str, dict[str, Any]]] = []
    for batch_dir in sorted(
        path for path in context_root.iterdir() if path.is_dir()
    ):
        packet_file = batch_dir / "review-packets.jsonl"
        if packet_file.is_file():
            packets.extend(
                (batch_dir.name, packet) for packet in read_jsonl(packet_file)
            )
    return packets


def dry_run_record(
    batch_id: str,
    packet: dict[str, Any],
    config: dict[str, Any],
    system_prompt: str,
) -> dict[str, Any]:
    user_prompt = build_user_prompt(packet)
    return {
        "mode": "dry-run",
        "provider": config.get("provider", "gemini"),
        "batch_id": batch_id,
        "packet_id": packet["packet_id"],
        "target_symbol": packet["target"]["symbol"],
        "model": config["model"],
        "reasoning_effort": config["reasoning_effort"],
        "prompt_version": config["prompt_version"],
        "estimated_input_tokens": max(
            1, (len(system_prompt) + len(user_prompt)) // 4
        ),
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "output_schema": review_schema(),
    }


def execute_review(
    client: ReviewerClient,
    packet: dict[str, Any],
    config: dict[str, Any],
    system_prompt: str,
) -> dict[str, Any]:
    last_error: Exception | None = None
    max_retries = int(config["max_retries"])
    for attempt in range(max_retries + 1):
        try:
            response = client.review(
                system_prompt, build_user_prompt(packet), review_schema()
            )
            validate_review(response.review, packet["packet_id"])
            return {
                "status": "completed",
                "packet_id": packet["packet_id"],
                "target_symbol": packet["target"]["symbol"],
                "prompt_version": config["prompt_version"],
                "response_id": response.response_id,
                "model": response.model,
                "usage": {
                    "input_tokens": response.input_tokens,
                    "output_tokens": response.output_tokens,
                    "total_tokens": response.total_tokens,
                },
                "latency_seconds": round(response.latency_seconds, 3),
                "review": response.review,
            }
        except Exception as error:
            last_error = error
            if attempt < max_retries:
                delay = float(config["retry_base_seconds"]) * (2**attempt)
                if "429" in str(error):
                    match = re.search(r"retry in ([0-9.]+)s", str(error), re.I)
                    if match:
                        delay = max(delay, float(match.group(1)) + 2)
                time.sleep(delay)
    return {
        "status": "failed",
        "packet_id": packet["packet_id"],
        "target_symbol": packet["target"]["symbol"],
        "prompt_version": config["prompt_version"],
        "error_type": type(last_error).__name__ if last_error else "UnknownError",
        "error": str(last_error) if last_error else "Unknown review error",
    }


def create_client(config: dict[str, Any]) -> ReviewerClient:
    provider = config.get("provider", "gemini")
    if provider == "gemini":
        return GeminiInteractionsReviewer(
            model=os.environ.get("GEMINI_MODEL", config["model"]),
            max_output_tokens=int(config["max_output_tokens"]),
            reasoning_effort=config.get("reasoning_effort", "low"),
        )
    if provider == "openai":
        return OpenAIResponsesReviewer(
            model=os.environ.get("OPENAI_MODEL", config["model"]),
            reasoning_effort=config["reasoning_effort"],
            max_output_tokens=int(config["max_output_tokens"]),
        )
    raise ValueError(f"Unsupported provider: {provider}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run or preview structured LLM security reviews."
    )
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--prompt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    config = read_json(args.config)
    system_prompt = args.prompt.read_text(encoding="utf-8")
    packets = load_packets(args.context)
    if args.limit is not None:
        packets = packets[:args.limit]
    args.output.mkdir(parents=True, exist_ok=True)

    if not args.execute:
        requests = [
            dry_run_record(batch_id, packet, config, system_prompt)
            for batch_id, packet in packets
        ]
        write_jsonl(args.output / "requests.jsonl", requests)
        manifest = {
            "mode": "dry-run",
            "provider": config.get("provider", "gemini"),
            "request_count": len(requests),
            "model": config["model"],
            "prompt_version": config["prompt_version"],
            "estimated_input_tokens": sum(
                request["estimated_input_tokens"] for request in requests
            ),
        }
        write_json(args.output / "manifest.json", manifest)
        print(
            f"dry-run: {len(requests)} requests, "
            f"{manifest['estimated_input_tokens']} estimated input tokens"
        )
        return 0

    provider = config.get("provider", "gemini")
    required_key = (
        "GEMINI_API_KEY" if provider == "gemini" else "OPENAI_API_KEY"
    )
    if not os.environ.get(required_key):
        parser.error(f"--execute requires {required_key}")

    client = create_client(config)
    reviews_path = args.output / "reviews.jsonl"
    existing = read_jsonl(reviews_path) if reviews_path.is_file() else []
    completed_by_id = {
        result["packet_id"]: result
        for result in existing
        if result.get("status") == "completed"
    }
    results = list(completed_by_id.values())
    pending = [
        (batch_id, packet) for batch_id, packet in packets
        if packet["packet_id"] not in completed_by_id
    ]
    if completed_by_id:
        print(
            f"resume: keeping {len(completed_by_id)} completed, "
            f"retrying {len(pending)} pending/failed"
        )
    interval = float(config.get("request_interval_seconds", 0))
    for index, (batch_id, packet) in enumerate(pending):
        if index and interval:
            time.sleep(interval)
        result = execute_review(client, packet, config, system_prompt)
        result["batch_id"] = batch_id
        results.append(result)
        write_jsonl(reviews_path, results)
        print(f"{packet['packet_id']}: {result['status']}")
        if result.get("error_type") == "RateLimitError":
            print(
                "rate limit remains exhausted; stopping so this run can be "
                "resumed after the quota resets"
            )
            break

    write_jsonl(reviews_path, results)
    completed = [result for result in results if result["status"] == "completed"]
    failed = [result for result in results if result["status"] == "failed"]
    manifest = {
        "mode": "execute",
        "provider": provider,
        "request_count": len(results),
        "completed": len(completed),
        "failed": len(failed),
        "prompt_version": config["prompt_version"],
        "usage": {
            key: sum(result["usage"][key] for result in completed)
            for key in ("input_tokens", "output_tokens", "total_tokens")
        },
        "latency_seconds": round(
            sum(result["latency_seconds"] for result in completed), 3
        ),
    }
    write_json(args.output / "manifest.json", manifest)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
