# Context Builder Analysis

## Purpose

The Context Builder prepares bounded inputs for a later Security Reviewer agent.
It selects High and Medium Candidate Finder results, extracts direct function
calls with Tree-sitter, and attaches available same-file function definitions
without exceeding the configured packet budget.

## Configuration

- Selected priorities: High and Medium
- Maximum estimated tokens per packet: 4,000
- Maximum related functions per packet: 3
- Maximum include directives per packet: 30
- Dependency depth: one direct-call level

The configuration is stored in `config/context-builder.json`.

## Results

| Batch | Review packets | Related functions | Packet tokens | Maximum packet | Over budget |
|---|---:|---:|---:|---:|---:|
| batch-01 | 1 | 3 | 1,936 | 1,936 | 0 |
| batch-02 | 2 | 2 | 3,813 | 2,752 | 0 |
| batch-03 | 13 | 24 | 14,129 | 2,762 | 0 |
| Total | 16 | 29 | 19,878 | 2,762 | 0 |

The selected target functions account for 14,835 estimated tokens. Direct
same-file dependencies add 5,043 estimated tokens. Compared with sending all
35,887 batch tokens, the final review packets reduce estimated code tokens by
44.61% while adding relevant local context.

## Packet contents

Each packet contains:

- Target function code and Candidate Finder metadata
- Original file and line range
- Risky API occurrences and priority score
- Source-file include directives
- Direct function-call names
- Same-file related function definitions that fit the budget
- External or unresolved call names
- Local calls omitted because of count or token limits
- Token-budget metrics

## Limitations

- Only direct calls are followed; transitive dependencies are not yet included.
- Resolution currently covers functions from the same analyzed source file.
- External library calls and functions defined outside the selected batch remain
  unresolved names.
- Include directives are recorded, but referenced type and macro definitions are
  not expanded yet.
- Token counts remain character-based estimates rather than model-tokenizer
  measurements.
- A missing dependency can affect the later AI review, so omitted and unresolved
  calls are explicitly retained in packet metadata.
