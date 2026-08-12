# Candidate Finder Analysis

## Purpose

The Candidate Finder reduces the number of function chunks sent to later AI
security-review agents. It searches function chunks for configured risky API
calls, records their original source locations, and assigns a deterministic
review priority.

The results are candidates for review, not confirmed vulnerabilities.

## Inputs and outputs

- Input: `results/chunks/<batch>/chunks.jsonl`
- Rules: `config/risky-apis.json`
- Output: `results/candidates/<batch>/candidates.jsonl`
- Summary: `results/candidates/<batch>/manifest.json`

The original chunk files are not modified.

## Scoring

Each configured API occurrence contributes its configured weight. A parse-error
chunk receives two additional points, and a chunk larger than 2,000 estimated
tokens receives one additional point.

- High priority: 8 points or more
- Medium priority: 4 to 7 points
- Low priority: fewer than 4 points

This score controls review order only. It is not a vulnerability severity score.

## Batch results

| Batch | Chunks | Candidate chunks | High priority | Total tokens | Candidate tokens | Estimated reduction |
|---|---:|---:|---:|---:|---:|---:|
| batch-01 | 44 | 1 | 1 | 10,000 | 1,709 | 82.91% |
| batch-02 | 18 | 4 | 1 | 5,090 | 3,850 | 24.36% |
| batch-03 | 75 | 21 | 4 | 20,797 | 10,425 | 49.87% |

If only chunks containing a configured risky API are sent to the next analysis
stage, the three batches decrease from an estimated 35,887 tokens to 15,984
tokens, a reduction of approximately 55.46% before adding prompts and context.

## Highest-priority candidates

| Batch | Function | Lines | Score | APIs |
|---|---|---:|---:|---|
| batch-01 | `raspicamcontrol_parse_cmdline` | 568-863 | 30 | `sscanf` |
| batch-02 | `OpenVideoCoreMemoryFileWithOffsetAndSize` | 184-493 | 17 | `calloc`, `free`, `malloc`, `open` |
| batch-03 | `dtoverlay_extract_override` | 1918-2145 | 12 | `sprintf`, `strcpy` |
| batch-03 | `dtoverlay_override_one_target` | 1499-1794 | 10 | `calloc`, `free`, `malloc`, `memcpy`, `sprintf` |
| batch-03 | `dtoverlay_foreach_override_target` | 1821-1902 | 9 | `free`, `malloc`, `memcpy`, `strcpy` |
| batch-03 | `dtoverlay_filter_symbols` | 1354-1442 | 8 | `free`, `malloc`, `strcpy` |

## Limitations

- API matching is a lexical prefilter and does not prove that a call is unsafe.
- Comments, macros, and unusual C syntax can produce false positives or misses.
- Token counts use the chunker's character-based estimate, not a model tokenizer.
- Dependencies, callers, type definitions, and relevant macros are not yet added
  to the candidate context.
- Functions without configured APIs can still contain vulnerabilities and are
  currently deprioritized rather than proven safe.
