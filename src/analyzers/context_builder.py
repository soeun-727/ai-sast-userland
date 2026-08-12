from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tree_sitter import Node

from src.chunker.tree_sitter_chunker import create_parser, walk


INCLUDE_PATTERN = re.compile(r"^\s*#\s*include\s+([<\"].*[>\"])")


def _last_identifier(node: Node, source: bytes) -> str | None:
    identifiers: list[str] = []
    for descendant in walk(node):
        if descendant.type in {"identifier", "field_identifier"}:
            identifiers.append(
                source[
                    descendant.start_byte:descendant.end_byte
                ].decode("utf-8", errors="replace")
            )
    return identifiers[-1] if identifiers else None


def extract_calls(code: str, language: str) -> list[str]:
    source = code.encode("utf-8")
    tree = create_parser(language).parse(source)
    calls: list[str] = []
    seen: set[str] = set()

    for node in walk(tree.root_node):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        if function is None:
            continue
        name = _last_identifier(function, source)
        if name and name not in seen:
            seen.add(name)
            calls.append(name)

    return calls


def read_includes(
    repository_root: Path,
    relative_path: str,
    limit: int,
) -> list[str]:
    source_path = repository_root / Path(relative_path)
    includes: list[str] = []
    with source_path.open(encoding="utf-8", errors="replace") as source:
        for line in source:
            match = INCLUDE_PATTERN.match(line)
            if match:
                includes.append(match.group(1))
                if len(includes) >= limit:
                    break
    return includes


class ContextBuilder:
    def __init__(self, config: dict[str, Any]) -> None:
        self.selected_priorities = set(config["selected_priorities"])
        self.max_tokens = int(config["max_packet_estimated_tokens"])
        self.max_related = int(config["max_related_functions"])
        self.max_includes = int(config["max_include_directives"])

    def should_build(self, candidate: dict[str, Any]) -> bool:
        return (
            candidate["priority"] in self.selected_priorities
            and int(candidate["risky_api_count"]) > 0
        )

    def build(
        self,
        candidate: dict[str, Any],
        batch_records: list[dict[str, Any]],
        includes: list[str],
    ) -> dict[str, Any]:
        symbol_index = {
            record["symbol"]: record
            for record in batch_records
            if record["relative_path"] == candidate["relative_path"]
        }
        calls = extract_calls(candidate["code"], candidate["language"])
        local_call_names = [name for name in calls if name in symbol_index]
        external_calls = [name for name in calls if name not in symbol_index]

        context_tokens = int(candidate["estimated_tokens"])
        related_functions: list[dict[str, Any]] = []
        omitted_local_calls: list[str] = []

        for name in local_call_names:
            if name == candidate["symbol"]:
                continue
            dependency = symbol_index[name]
            dependency_tokens = int(dependency["estimated_tokens"])
            if len(related_functions) >= self.max_related:
                omitted_local_calls.append(name)
                continue
            if context_tokens + dependency_tokens > self.max_tokens:
                omitted_local_calls.append(name)
                continue

            related_functions.append(
                {
                    "chunk_id": dependency["chunk_id"],
                    "symbol": dependency["symbol"],
                    "relative_path": dependency["relative_path"],
                    "start_line": dependency["start_line"],
                    "end_line": dependency["end_line"],
                    "estimated_tokens": dependency_tokens,
                    "risky_apis": dependency.get("risky_apis", []),
                    "code": dependency["code"],
                }
            )
            context_tokens += dependency_tokens

        packet = {
            "packet_id": f"review-{candidate['chunk_id']}",
            "batch_id": candidate.get("batch_id"),
            "target": candidate,
            "context": {
                "include_directives": includes[:self.max_includes],
                "function_calls": calls,
                "external_calls": external_calls,
                "related_functions": related_functions,
                "omitted_local_calls": omitted_local_calls,
            },
            "context_metrics": {
                "target_estimated_tokens": candidate["estimated_tokens"],
                "related_function_count": len(related_functions),
                "packet_estimated_tokens": context_tokens,
                "token_budget": self.max_tokens,
                "target_exceeds_budget": (
                    int(candidate["estimated_tokens"]) > self.max_tokens
                ),
            },
        }
        return packet
