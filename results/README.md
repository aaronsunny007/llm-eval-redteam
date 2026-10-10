# Results

Each committed run directory contains:

| File | Contents |
|---|---|
| `report.md` | Human-readable report: defence table, per-category results, judge validation |
| `summary.json` | Every number in the report, machine-readable |
| `chart.svg` | Attack success vs. benign refusal by defence, with 95% intervals |
| `transcripts.jsonl` | Every response, per case and defence |
| `judgements.<judge>.jsonl` | Every verdict and its rationale, per judge |
| `guard_log.jsonl` | Why each guard fired |

Directories starting with `_` are scratch runs and are git-ignored.
