from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


VALID_DISPOSITIONS = {"confirmed", "likely", "false_positive"}


def source_excerpt(path: Path, start: int, end: int, padding: int = 3) -> dict[str, Any]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if start < 1 or end < start or start > len(lines):
        raise ValueError(f"invalid source range {start}-{end} for {path}")
    first = max(1, start - padding)
    last = min(len(lines), end + padding)
    text = "\n".join(f"{number}: {lines[number - 1]}" for number in range(first, last + 1))
    return {
        "start_line": first,
        "end_line": last,
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "text": text,
    }


def validate_finding(
    result: dict[str, Any],
    finding: dict[str, Any],
    repository: Path,
    decisions: dict[str, Any],
) -> dict[str, Any]:
    decision_key = f"{result['packet_id']}::{finding['finding_id']}"
    if decision_key not in decisions:
        raise ValueError(f"missing validator decision: {decision_key}")
    decision = decisions[decision_key]
    disposition = decision["disposition"]
    if disposition not in VALID_DISPOSITIONS:
        raise ValueError(f"invalid disposition: {disposition}")

    relative_path = finding["file"].replace("/", str(Path("/"))).replace("\\", str(Path("/")))
    relative_path = relative_path.replace(str(Path("/")), "/")
    source_path = repository / Path(relative_path)
    if not source_path.is_file():
        raise FileNotFoundError(source_path)

    excerpt = source_excerpt(
        source_path, int(finding["start_line"]), int(finding["end_line"])
    )
    duplicate_key = decision.get(
        "duplicate_key",
        f"{relative_path}:{finding['start_line']}:{finding['cwe_id']}",
    )
    return {
        "validation_id": hashlib.sha256(decision_key.encode()).hexdigest()[:16],
        "packet_id": result["packet_id"],
        "batch_id": result["batch_id"],
        "target_symbol": result["target_symbol"],
        "finding_id": finding["finding_id"],
        "title": finding["title"],
        "cwe_id": finding["cwe_id"],
        "severity": finding["severity"],
        "model_confidence": finding["confidence"],
        "file": relative_path,
        "start_line": finding["start_line"],
        "end_line": finding["end_line"],
        "disposition": disposition,
        "validator_confidence": decision["confidence"],
        "rationale": decision["rationale"],
        "attack_surface": decision["attack_surface"],
        "duplicate_key": duplicate_key,
        "source_verified": True,
        "source_excerpt": excerpt,
        "remediation": finding["remediation"],
    }


def deduplicate(validations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rank = {"confirmed": 2, "likely": 1, "false_positive": 0}
    selected: dict[str, dict[str, Any]] = {}
    for item in validations:
        key = item["duplicate_key"]
        current = selected.get(key)
        if current is None or (
            rank[item["disposition"]], item["validator_confidence"]
        ) > (rank[current["disposition"]], current["validator_confidence"]):
            selected[key] = item
    return list(selected.values())
