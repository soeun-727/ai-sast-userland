from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKDOWN = [
    path for path in sorted(ROOT.rglob("*.md"))
    if not any(part in {".venv", ".git", "tools"} for part in path.parts)
]
STALE = (
    "Cppcheck 실행 결과는 아직",
    "Live security findings have not yet been generated",
    "Cppcheck 기준 결과를 아직 확보",
)


def main() -> int:
    errors: list[str] = []
    for path in MARKDOWN:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            errors.append(f"invalid UTF-8: {path.relative_to(ROOT)}: {error}")
            continue
        for phrase in STALE:
            if phrase in text:
                errors.append(f"stale phrase in {path.relative_to(ROOT)}: {phrase}")
        for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
            if re.match(r"(?:https?://|#)", target):
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                errors.append(f"broken link in {path.relative_to(ROOT)}: {target}")

    report = (ROOT / "docs/final-report.md").read_text(encoding="utf-8")
    required = (
        "Agent 구성도", "Agent skill 작성 시 주안점",
        "토큰 절약 설계와 도입 이유", "작성한 프롬프트",
        "기존 SAST와의 비교", "재현 방법",
    )
    for heading in required:
        if heading not in report:
            errors.append(f"final report missing required content: {heading}")

    review = json.loads((ROOT / "results/security-reviews/manifest.json").read_text())
    validation = json.loads((ROOT / "results/validation/manifest.json").read_text())
    expected = (
        f"LLM 검토 패킷: {review['request_count']}개",
        f"합계 {review['usage']['total_tokens']:,}토큰",
        f"confirmed {validation['confirmed']}건",
        f"likely {validation['likely']}건",
    )
    for value in expected:
        if value not in report:
            errors.append(f"final report result mismatch: {value}")

    if errors:
        print("\n".join(f"ERROR: {error}" for error in errors))
        return 1
    print(f"markdown audit: {len(MARKDOWN)} files, no broken links or stale result claims")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
