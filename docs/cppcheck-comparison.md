# Cppcheck Comparison

## Setup

- Tool: Cppcheck 2.21.0 official Windows x64 release
- Target commit: `a54a0dbb2b8dcf9bafdddfc9a9374fb51d97e976`
- Options: warning, style, performance, portability, inconclusive,
  exhaustive checking, unix64 platform
- Missing system includes were suppressed because the Raspberry Pi/Linux target
  is analyzed from Windows.

The MSI required administrator privileges for system registration, so it was
administratively extracted under `tools/cppcheck` and invoked directly. That
directory is ignored by Git; the exact execution command is recorded in each
runtime JSON file.

## Results

| Scope | Time | Total diagnostics | Error/warning diagnostics |
|---|---:|---:|---:|
| AI-matched 3 files | 1.212 s | 84 | 7 |
| Entire userland repository | 60.648 s | 1,637 | 459 |

The matched-scope diagnostics consist of 77 style and 7 warning results. The
full scan consists of 1,133 style, 208 warning, 45 portability, and 251 error
results. Counts are raw diagnostics and are not equivalent to verified security
vulnerabilities. In particular, whole-repository errors can include missing
target build configuration and preprocessing issues.

## AI comparison

| Category | Count |
|---|---:|
| Validated AI findings | 9 |
| Common findings | 1 |
| AI-only findings | 8 |
| Cppcheck error/warning results unmatched by AI | 6 |

The common finding is the unchecked allocation in `dtoverlay_dup_property`,
reported by Cppcheck as `nullPointerOutOfMemory` (CWE-476). A candidate match
requires the same normalized file and a Cppcheck primary line inside the AI
range or within three lines of its sink, followed by semantic confirmation.

Cppcheck did not report the eight other validated AI findings, including
unbounded string copies, arithmetic overflow, and partial cleanup on an error
path. Conversely, Cppcheck reported format-string type mismatches that the
bounded AI packet review did not select as findings.

## Artifacts

- `results/cppcheck/full-scope.xml`
- `results/cppcheck/matched-scope.xml`
- `results/cppcheck/comparison.json`
- `results/cppcheck/ai-vs-cppcheck.csv`
- `results/cppcheck/*-runtime.json`
