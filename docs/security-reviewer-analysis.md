# Security Reviewer

## Purpose

The Security Reviewer sends bounded Context Builder packets to an LLM and
requires a strict, evidence-based security review result. Risky API matches are
treated as leads rather than confirmed vulnerabilities.

## Implementation

- API: Gemini Developer API (Interactions API)
- SDK: `google-genai`
- Default model: `gemini-3.6-flash`
- Thinking level: `low`
- Structured output: strict JSON Schema
- Maximum output tokens: 5,000
- Retry count: 2
- Request interval: 4 seconds (free-tier rate-limit protection)
- Prompt version: `security-reviewer-v1`

The model can be overridden with the `GEMINI_MODEL` environment variable.
The OpenAI provider remains available only as an optional comparison target.

## Output fields

Each completed response records:

- Verdict: `no_finding`, `findings`, or `insufficient_context`
- CWE, severity, confidence, source range, and visible evidence
- Attack preconditions and remediation
- Missing context
- Model and response identifier
- Input, output, and total API token usage
- Request latency

## Dry-run result

The dry-run generated 16 requests without making an API call.

| Batch | Requests | Estimated input tokens | Largest request |
|---|---:|---:|---:|
| batch-01 | 1 | 3,877 | 3,877 |
| batch-02 | 2 | 6,393 | 4,373 |
| batch-03 | 13 | 27,929 | 4,332 |
| Total | 16 | 38,199 | 4,373 |

The earlier 4,000-token Context Builder limit applies to estimated source-code
context. Full requests also contain instructions, metadata, and a serialized
output schema, so their estimates are slightly larger. Actual API usage is
recorded from the response rather than inferred from this estimate.

## Execution

Do not save an API key in the repository. Set it only in the process environment
and run:

```powershell
$env:GEMINI_API_KEY = "your-key"
.\.venv\Scripts\python.exe .\scripts\review_security.py `
    --context .\results\context `
    --config .\config\security-reviewer.json `
    --prompt .\prompts\security-reviewer-system.md `
    --output .\results\security-reviews `
    --execute
```

Use `--limit 1` for the first smoke test. The key should be removed from the
current PowerShell process after execution:

```powershell
Remove-Item Env:GEMINI_API_KEY
```

Execution is resumable. Completed packets in `reviews.jsonl` are retained and
only failed or missing packets are sent again. Results are checkpointed after
every packet. For HTTP 429 responses, the runner honors Gemini's reported retry
delay before retrying. If the quota is still exhausted after all retries, the
run stops instead of sending the remaining packets; the same command resumes
them after the quota resets.

## Current status

All 16 packets completed successfully. The final run recorded 54,995 input,
5,203 output, and 69,567 total tokens with 374.346 seconds of API latency.
Eight packets returned `findings`, eight returned `no_finding`, and the nine raw
findings were passed to the Validator Agent. Earlier JSON truncation was fixed
by increasing the output budget and using low thinking; free-tier 429 failures
were handled by checkpointed resume and quota-aware stopping.
