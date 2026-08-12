# Validator Agent

## Purpose

The Validator Agent checks every Security Reviewer finding against the pinned
Raspberry Pi userland source. It records the exact source excerpt and SHA-256,
assesses reachability and missing guards, assigns a disposition, and collapses
findings that share a duplicate key.

## Classification policy

- `confirmed`: the reported unsafe operation and the required missing guard are
  visible in the supplied source; the attack or failure precondition is stated.
- `likely`: the unsafe operation is visible, but full exploitability depends on
  constraints outside the bounded context.
- `false_positive`: the source contradicts the report or a dominating guard
  prevents the reported behavior.

Decisions are kept in `config/validator-decisions.json` so that manual judgment
is reviewable separately from the validation engine. The engine fails closed if
a generated finding has no corresponding decision.

## Result

| Metric | Count |
|---|---:|
| Security Reviewer findings | 9 |
| Source ranges verified | 9 |
| Deduplicated findings | 9 |
| Confirmed | 7 |
| Likely | 2 |
| False positive | 0 |

The resource-leak finding required a correction to the model's explanation.
The error path does free the outer handle, but it does not release the allocated
symbol table or symbol-label strings, so the final disposition remains
`confirmed` with revised evidence.

The two `likely` findings are the unbounded overlay-map path formatting and the
signed dynamic-string growth overflow. Both sinks are present, while practical
reachability depends on upstream path-length, DTB-size, and process constraints.

## Reproduction

```powershell
.\.venv\Scripts\python.exe .\scripts\validate_findings.py `
  --reviews .\results\security-reviews\reviews.jsonl `
  --decisions .\config\validator-decisions.json `
  --repo ..\userland `
  --output .\results\validation
```

Outputs are `validations.jsonl`, `deduplicated-findings.jsonl`, and
`manifest.json` under `results/validation`.
