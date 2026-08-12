from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.analyzers.context_builder import ContextBuilder, read_includes


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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build token-bounded security review context packets."
    )
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    builder = ContextBuilder(read_json(args.config))
    repository_root = args.repo.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    overall = {"batches": []}

    batch_dirs = sorted(
        path
        for path in args.candidates.iterdir()
        if path.is_dir() and (path / "candidates.jsonl").is_file()
    )

    for batch_dir in batch_dirs:
        output_dir = args.output / batch_dir.name
        output_dir.mkdir(parents=True, exist_ok=True)
        records = read_jsonl(batch_dir / "candidates.jsonl")
        for record in records:
            record["batch_id"] = batch_dir.name

        selected = [record for record in records if builder.should_build(record)]
        include_cache: dict[str, list[str]] = {}
        packets = []
        for candidate in selected:
            relative_path = candidate["relative_path"]
            if relative_path not in include_cache:
                include_cache[relative_path] = read_includes(
                    repository_root,
                    relative_path,
                    builder.max_includes,
                )
            packets.append(
                builder.build(
                    candidate,
                    records,
                    include_cache[relative_path],
                )
            )

        packet_tokens = sum(
            packet["context_metrics"]["packet_estimated_tokens"]
            for packet in packets
        )
        related_count = sum(
            packet["context_metrics"]["related_function_count"]
            for packet in packets
        )
        manifest = {
            "batch_id": batch_dir.name,
            "input_chunks": len(records),
            "review_packets": len(packets),
            "related_functions_included": related_count,
            "packet_estimated_tokens": packet_tokens,
            "packets_over_budget": sum(
                1
                for packet in packets
                if packet["context_metrics"]["target_exceeds_budget"]
            ),
        }
        write_jsonl(output_dir / "review-packets.jsonl", packets)
        write_json(output_dir / "manifest.json", manifest)
        overall["batches"].append(manifest)

        print(
            f"{batch_dir.name}: {len(packets)} review packets, "
            f"{related_count} related functions, "
            f"{packet_tokens} estimated tokens"
        )

    write_json(args.output / "manifest.json", overall)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
