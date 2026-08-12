from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.reporters.report_builder import build_report


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def read_first_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the final AI SAST report deterministically.")
    parser.add_argument("--project", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.project.resolve()
    commit_lines = read_first_lines(root / "results/baseline/target-commit.txt")
    data = {
        "target": {
            "url": (root / "results/baseline/target-url.txt").read_text(encoding="utf-8").strip(),
            "commit": commit_lines[0].strip(),
        },
        "review_manifest": read_json(root / "results/security-reviews/manifest.json"),
        "validation_manifest": read_json(root / "results/validation/manifest.json"),
        "findings": read_jsonl(root / "results/validation/deduplicated-findings.jsonl"),
        "cppcheck": read_json(root / "results/cppcheck/comparison.json"),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(build_report(data), encoding="utf-8")
    print(f"report: {args.output} ({len(data['findings'])} findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
