from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path


MATCHED_FILES = [
    "host_applications/linux/apps/raspicam/RaspiCamControl.c",
    "host_applications/linux/libs/debug_sym/debug_sym.c",
    "helpers/dtoverlay/dtoverlay.c",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run reproducible Cppcheck baselines.")
    parser.add_argument("--cppcheck", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scope", choices=("matched", "full"), required=True)
    args = parser.parse_args()

    executable = args.cppcheck.resolve()
    repository = args.repo.resolve()
    targets = (
        [repository / path for path in MATCHED_FILES]
        if args.scope == "matched"
        else [repository]
    )
    command = [
        str(executable), *(str(path) for path in targets),
        "--enable=warning,style,performance,portability", "--inconclusive",
        "--check-level=exhaustive", "--platform=unix64",
        "--suppress=missingIncludeSystem", "--xml", "--xml-version=2",
    ]
    args.output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    process = subprocess.run(command, capture_output=True, check=False)
    elapsed = time.perf_counter() - started
    (args.output / f"{args.scope}-scope.xml").write_bytes(process.stderr)
    (args.output / f"{args.scope}-progress.txt").write_bytes(process.stdout)
    version = subprocess.run(
        [str(executable), "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    runtime = {
        "scope": args.scope,
        "version": version,
        "exit_code": process.returncode,
        "seconds": round(elapsed, 3),
        "target_count": len(targets) if args.scope == "matched" else None,
        "command": command,
    }
    (args.output / f"{args.scope}-runtime.json").write_text(
        json.dumps(runtime, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"cppcheck {args.scope}: exit={process.returncode}, {elapsed:.3f}s")
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
