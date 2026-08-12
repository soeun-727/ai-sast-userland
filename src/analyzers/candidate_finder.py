from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ApiRule:
    name: str
    category: str
    weight: int
    pattern: re.Pattern[str]


class CandidateFinder:
    def __init__(self, config: dict[str, Any]) -> None:
        self.rules = [
            ApiRule(
                name=name,
                category=rule["category"],
                weight=int(rule["weight"]),
                pattern=re.compile(rf"\b{re.escape(name)}\s*\("),
            )
            for name, rule in config["apis"].items()
        ]
        self.scoring = config["scoring"]
        self.priority_thresholds = config["priority"]

    def analyze(self, chunk: dict[str, Any]) -> dict[str, Any]:
        occurrences: list[dict[str, Any]] = []
        score = 0

        for local_line, source_line in enumerate(
            chunk["code"].splitlines(),
        ):
            for rule in self.rules:
                matches = list(rule.pattern.finditer(source_line))
                for match in matches:
                    occurrences.append(
                        {
                            "api": rule.name,
                            "category": rule.category,
                            "line": chunk["start_line"] + local_line,
                            "column": match.start() + 1,
                            "code": source_line.strip(),
                            "weight": rule.weight,
                        }
                    )
                    score += rule.weight

        score_reasons: list[dict[str, Any]] = []
        if chunk.get("has_parse_error", False):
            bonus = int(self.scoring["parse_error_bonus"])
            score += bonus
            score_reasons.append(
                {"reason": "parse_error", "points": bonus}
            )

        threshold = int(self.scoring["large_chunk_threshold"])
        if int(chunk.get("estimated_tokens", 0)) > threshold:
            bonus = int(self.scoring["large_chunk_bonus"])
            score += bonus
            score_reasons.append(
                {"reason": "large_chunk", "points": bonus}
            )

        api_counts = Counter(item["api"] for item in occurrences)
        category_counts = Counter(
            item["category"] for item in occurrences
        )

        enriched = dict(chunk)
        enriched.update(
            {
                "risky_apis": sorted(api_counts),
                "risky_api_count": len(occurrences),
                "risky_api_counts": dict(sorted(api_counts.items())),
                "risky_category_counts": dict(
                    sorted(category_counts.items())
                ),
                "api_occurrences": occurrences,
                "priority_score": score,
                "priority": self._priority(score),
                "score_reasons": score_reasons,
            }
        )
        return enriched

    def _priority(self, score: int) -> str:
        if score >= int(self.priority_thresholds["high"]):
            return "high"
        if score >= int(self.priority_thresholds["medium"]):
            return "medium"
        return "low"
