from __future__ import annotations

import argparse
import csv
import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def warnings(path: Path) -> list[dict[str, Any]]:
    # Cppcheck 2.21 on Windows emits the localized path bytes using the active
    # console encoding while declaring UTF-8. Replacement preserves the path
    # suffixes and all diagnostic fields needed for comparison.
    xml_text = path.read_bytes().decode("utf-8", errors="replace")
    root = ET.fromstring(xml_text)
    output = []
    for error in root.findall("./errors/error"):
        locations = error.findall("location")
        primary = locations[0] if locations else None
        output.append({
            "id": error.get("id", ""),
            "severity": error.get("severity", ""),
            "cwe": f"CWE-{error.get('cwe')}" if error.get("cwe") else "",
            "message": error.get("msg", ""),
            "file": (primary.get("file", "") if primary is not None else "").replace("\\", "/"),
            "line": int(primary.get("line", "0")) if primary is not None else 0,
        })
    return output


def same_file(cppcheck_file: str, ai_file: str) -> bool:
    return cppcheck_file.lower().endswith(ai_file.replace("\\", "/").lower())


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare validated AI findings with Cppcheck XML.")
    parser.add_argument("--ai", type=Path, required=True)
    parser.add_argument("--matched", type=Path, required=True)
    parser.add_argument("--full", type=Path, required=True)
    parser.add_argument("--matched-runtime", type=Path, required=True)
    parser.add_argument("--full-runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    ai = read_jsonl(args.ai)
    matched = warnings(args.matched)
    full = warnings(args.full)
    rows = []
    matched_warning_indexes: set[int] = set()
    for finding in ai:
        overlaps = []
        for index, warning in enumerate(matched):
            line_overlap = finding["start_line"] <= warning["line"] <= finding["end_line"]
            near_sink = abs(warning["line"] - finding["start_line"]) <= 3
            if same_file(warning["file"], finding["file"]) and (line_overlap or near_sink):
                overlaps.append(warning)
                matched_warning_indexes.add(index)
        rows.append({
            "ai_title": finding["title"],
            "ai_disposition": finding["disposition"],
            "ai_cwe": finding["cwe_id"],
            "file": finding["file"],
            "line": finding["start_line"],
            "comparison": "common" if overlaps else "ai_only",
            "cppcheck_ids": ", ".join(sorted({item["id"] for item in overlaps})),
            "cppcheck_lines": ", ".join(str(item["line"]) for item in overlaps),
        })

    security_severities = {"error", "warning"}
    summary = {
        "cppcheck_version": read_json(args.matched_runtime)["version"],
        "matched_scope": {
            "files": 3,
            "seconds": read_json(args.matched_runtime)["seconds"],
            "warnings_total": len(matched),
            "security_relevant_warnings": sum(w["severity"] in security_severities for w in matched),
            "by_severity": dict(Counter(w["severity"] for w in matched)),
            "by_id": dict(Counter(w["id"] for w in matched)),
        },
        "full_scope": {
            "seconds": read_json(args.full_runtime)["seconds"],
            "warnings_total": len(full),
            "security_relevant_warnings": sum(w["severity"] in security_severities for w in full),
            "by_severity": dict(Counter(w["severity"] for w in full)),
            "top_ids": dict(Counter(w["id"] for w in full).most_common(15)),
        },
        "comparison": {
            "ai_findings": len(ai),
            "common": sum(row["comparison"] == "common" for row in rows),
            "ai_only": sum(row["comparison"] == "ai_only" for row in rows),
            "cppcheck_matched_scope_unmatched_warnings": len(matched) - len(matched_warning_indexes),
            "cppcheck_security_unmatched": sum(
                index not in matched_warning_indexes
                and warning["severity"] in security_severities
                for index, warning in enumerate(matched)
            ),
        },
        "method": "Same normalized file and Cppcheck primary line inside the AI range or within 3 lines of its reported sink; common matches require manual semantic confirmation.",
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "comparison.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with (args.output / "ai-vs-cppcheck.csv").open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
