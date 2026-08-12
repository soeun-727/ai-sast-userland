from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.validators.finding_validator import deduplicate, validate_finding


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def write_jsonl(path: Path, values: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(v, ensure_ascii=False) + "\n" for v in values), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate LLM SAST findings against source.")
    parser.add_argument("--reviews", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    decisions = read_json(args.decisions)["decisions"]
    validations = []
    for result in read_jsonl(args.reviews):
        if result.get("status") != "completed":
            continue
        for finding in result["review"]["findings"]:
            validations.append(validate_finding(result, finding, args.repo, decisions))

    deduped = deduplicate(validations)
    args.output.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output / "validations.jsonl", validations)
    write_jsonl(args.output / "deduplicated-findings.jsonl", deduped)
    counts = Counter(item["disposition"] for item in deduped)
    manifest = {
        "input_findings": len(validations),
        "deduplicated_findings": len(deduped),
        "confirmed": counts["confirmed"],
        "likely": counts["likely"],
        "false_positive": counts["false_positive"],
        "source_verified": sum(item["source_verified"] for item in validations),
    }
    write_json(args.output / "manifest.json", manifest)
    print(
        f"validated {len(validations)} findings: {counts['confirmed']} confirmed, "
        f"{counts['likely']} likely, {counts['false_positive']} false positive"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
