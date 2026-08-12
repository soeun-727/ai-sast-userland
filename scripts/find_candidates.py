from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.analyzers.candidate_finder import CandidateFinder


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as source:
        return [json.loads(line) for line in source if line.strip()]


def write_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record, ensure_ascii=False) + "\n")


def build_manifest(
    batch_id: str,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    priority_counts = Counter(record["priority"] for record in records)
    api_counts: Counter[str] = Counter()
    total_tokens = 0
    candidate_tokens = 0

    for record in records:
        api_counts.update(record["risky_api_counts"])
        tokens = int(record["estimated_tokens"])
        total_tokens += tokens
        if record["risky_api_count"] > 0:
            candidate_tokens += tokens

    candidates = [
        record for record in records if record["risky_api_count"] > 0
    ]
    high_priority = [
        record for record in records if record["priority"] == "high"
    ]

    return {
        "batch_id": batch_id,
        "total_chunks": len(records),
        "candidate_chunks": len(candidates),
        "high_priority_chunks": len(high_priority),
        "priority_counts": {
            name: priority_counts.get(name, 0)
            for name in ("high", "medium", "low")
        },
        "api_counts": dict(api_counts.most_common()),
        "total_estimated_tokens": total_tokens,
        "candidate_estimated_tokens": candidate_tokens,
        "estimated_tokens_avoided": total_tokens - candidate_tokens,
        "candidate_token_reduction_percent": round(
            100 * (total_tokens - candidate_tokens) / total_tokens,
            2,
        ) if total_tokens else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find and prioritize risky API candidates in chunks."
    )
    parser.add_argument("--chunks", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    finder = CandidateFinder(read_json(args.config))
    args.output.mkdir(parents=True, exist_ok=True)
    overall = {"batches": []}

    batch_dirs = sorted(
        path
        for path in args.chunks.iterdir()
        if path.is_dir() and (path / "chunks.jsonl").is_file()
    )

    for batch_dir in batch_dirs:
        output_dir = args.output / batch_dir.name
        output_dir.mkdir(parents=True, exist_ok=True)

        chunks = read_jsonl(batch_dir / "chunks.jsonl")
        records = [finder.analyze(chunk) for chunk in chunks]
        records.sort(
            key=lambda record: (
                -record["priority_score"],
                record["relative_path"],
                record["start_line"],
            )
        )

        manifest = build_manifest(batch_dir.name, records)
        write_jsonl(output_dir / "candidates.jsonl", records)
        write_json(output_dir / "manifest.json", manifest)
        overall["batches"].append(manifest)

        print(
            f"{batch_dir.name}: {manifest['total_chunks']} chunks, "
            f"{manifest['candidate_chunks']} candidates, "
            f"{manifest['high_priority_chunks']} high priority, "
            f"{manifest['candidate_token_reduction_percent']}% "
            "estimated token reduction"
        )

    write_json(args.output / "manifest.json", overall)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
