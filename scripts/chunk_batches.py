from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.chunker.tree_sitter_chunker import chunk_source_file


BATCHES = [
    {
        "id": "batch-01",
        "file": (
            "host_applications/linux/apps/raspicam/"
            "RaspiCamControl.c"
        ),
    },
    {
        "id": "batch-02",
        "file": (
            "host_applications/linux/libs/debug_sym/"
            "debug_sym.c"
        ),
    },
    {
        "id": "batch-03",
        "file": "helpers/dtoverlay/dtoverlay.c",
    },
]


def write_json(path: Path, data: object) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_jsonl(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as output:
        for record in records:
            output.write(
                json.dumps(record, ensure_ascii=False) + "\n"
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Split selected C/C++ files into function chunks."
    )
    parser.add_argument(
        "--repo",
        type=Path,
        required=True,
        help="Target repository root",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "results" / "chunks",
    )
    args = parser.parse_args()

    repository_root = args.repo.resolve()
    output_root = args.output.resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    overall_manifest = {
        "repository": str(repository_root),
        "batches": [],
    }

    for batch in BATCHES:
        source_path = repository_root / batch["file"]
        batch_output = output_root / batch["id"]
        batch_output.mkdir(parents=True, exist_ok=True)

        if not source_path.is_file():
            raise FileNotFoundError(source_path)

        chunks, file_manifest = chunk_source_file(
            source_path=source_path,
            repository_root=repository_root,
        )

        chunk_records = [chunk.to_dict() for chunk in chunks]

        write_jsonl(
            batch_output / "chunks.jsonl",
            chunk_records,
        )

        batch_manifest = {
            "batch_id": batch["id"],
            **file_manifest,
            "total_estimated_tokens": sum(
                chunk.estimated_tokens for chunk in chunks
            ),
            "largest_chunk_tokens": max(
                (
                    chunk.estimated_tokens
                    for chunk in chunks
                ),
                default=0,
            ),
            "parse_error_chunks": sum(
                1 for chunk in chunks if chunk.has_parse_error
            ),
        }

        write_json(
            batch_output / "manifest.json",
            batch_manifest,
        )

        overall_manifest["batches"].append(batch_manifest)

        print(
            f"{batch['id']}: "
            f"{file_manifest['function_count']} functions, "
            f"{batch_manifest['total_estimated_tokens']} "
            "estimated tokens"
        )

    write_json(
        output_root / "manifest.json",
        overall_manifest,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())