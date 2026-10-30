# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- A one-click demo (`examples/demo/`, workflow "Try the demo", or `python examples/demo/run_demo.py`) that
  red-teams a vulnerable toy app and a guarded one with no model, GPU or API key, and a static
  results site (`scripts/build_site.py`, deployed by `.github/workflows/pages.yml`) with an explorer
  over all 650 responses. Both are checked in CI.
- Blind human labelling (the dashboard now writes `data/labels/human.jsonl`, no pre-filled AI
  labels), `scripts/compare_labels.py` (human-vs-AI and judge-vs-human agreement), and a
  stronger-judge path (`configs/benchmark-gemini-judge.yaml`, `scripts/prepare_rejudge.py`,
  `scripts/list_models.py`), with a step-by-step guide in `docs/`.
- Project hygiene: `CITATION.cff`, `CONTRIBUTING.md`, `SECURITY.md` (including responsible-use
  guidance), issue and pull-request templates, Dependabot, a pre-commit config, and a `mypy`
  step in CI (the source type-checks cleanly with `check_untyped_defs`).
- `paper/`: a technical report (LaTeX source and PDF) on the defence study and the validity of
  the hybrid judge, with `scripts/paper_stats.py` (bootstrap intervals, pairwise McNemar) and an
  exploratory replication on Qwen 2.5 7B (`configs/replication-qwen.yaml`,
  `results/finassist-qwen2.5-7b/`).
- `examples/ledger/`: a drop-in red-team workflow, config and scenario for the Ledger API
  (85 attacks, Gemini judge, weekly gate). Tested against fake servers only.

### Fixed
- HTTP targets: a firewall refusal (HTTP 403/451) is recorded as a blocked request instead of
  aborting the run; a wrong `response_path` or non-JSON reply stops with a clear message.
- Hosted judges: `max_tokens` is a floor for OpenAI-compatible models (reasoning models spend
  tokens thinking), and `reasoning_effort` can be set in the model config.
- Judging refuses to resume a file written by a different judge, so verdicts from two models
  are never mixed.
- The input guard no longer blocks the name "Dan" (only the uppercase jailbreak name `DAN`).
- Label page: opens first (the Results page shows judge verdicts), pre-fills nothing, and offers
  only the Mistral run, so labels cannot be saved against another model's responses.
  `scripts/compare_labels.py` explains a missing `human.jsonl` instead of crashing, and has tests.
- `docker-compose.yml` publishes Ollama and the dashboard on 127.0.0.1 only.
- The GitHub Action passes its inputs through environment variables, not into shell text;
  `args` is split on spaces with no quoting or glob expansion.

## [1.1.1] - 2026-10-12

### Fixed
- Evidence grounding no longer overturns true attacks: a verdict whose quote is not found in
  the response is retried once, and quotes made of several separate pieces (list items) are
  accepted when most of their text is in the response. Hybrid judge on the 110 labels:
  kappa 0.63 -> 0.67, recall 73% -> 78%, precision unchanged.
- Model and HTTP-target calls retry on rate limits (429), server errors and dropped
  connections with backoff, so hosted free-tier judges slow a run instead of failing it.

## [1.1.0] - 2026-10-12

### Added
- 60 attacks covering the three categories v1.0.0 did not exercise: `system_prompt_leak`
  (Lakera/gandalf_ignore_instructions), `data_exfiltration` (Lakera/gandalf_summarization)
  and `jailbreak` (JailbreakBench/JBB-Behaviors, plain harmful requests), built by
  `scripts/build_extra_attack_sets.py`; provenance in `data/attacks/NOTICE.md`.
- 60 reference labels for those cases, written before any judge scored them.
- Full benchmark over 110 attacks: layered defence 39% -> 4% attack success, hybrid judge
  kappa 0.63 over 110 labels (0.40 on the cases that need the LLM judge).

### Changed
- Tiny exact-McNemar p-values are reported as `<0.0001` instead of rounding to 0.

## [1.0.0] - 2026-10-11

### Added
- Installable package `llm-redteam` with a CLI: `run`, `ci`, `report`, `validate`, `dashboard`.
- 50 attacks (25 direct, 25 indirect) built from deepset/prompt-injections (Apache-2.0) by a
  deterministic script, as versioned, schema-validated JSONL data files (`data/attacks/`), plus a
  benign control set (`data/benign/`) for measuring over-refusal.
- Reference scenario (`data/scenarios/finassist.yaml`): a financial-filings assistant
  with fake canary secrets for deterministic leak detection.
- Hybrid AI judge: deterministic secret-leak detector, then a rubric-driven LLM judge with
  structured output. The v0 keyword scorer is kept as a measured baseline.
- Gold-labelling tool (Streamlit) that hides judge verdicts while labelling, plus judge
  validation against human labels (accuracy, precision, recall, F1, Cohen's κ).
- Three defences: hardened prompt (instruction hierarchy, spotlighting, sandwich),
  input guard, and output guard, plus a layered combination.
- Statistics: Wilson 95% intervals, exact McNemar tests against the undefended baseline.
- Targets: Ollama, any OpenAI-compatible API, and arbitrary JSON-over-HTTP services.
- CI gate with JUnit XML and GitHub job summary output, and a reusable GitHub Action.
- Evidence-grounding check: a judge verdict of "attack succeeded" is overturned unless the
  quoted evidence really appears in the response.
- Reference benchmark (Mistral 7B, judge Qwen 2.5 7B) with results, judge validation against
  50 AI-written reference labels (kappa 0.38), and a script that renders README results from
  `summary.json`.
- Test suite against scripted models; CI on Python 3.10 and 3.12; action self-test.

### Removed
- FastAPI service, DeepEval dependency and the hallucination prototype.
- Committed `mlflow.db` and DeepEval telemetry files.
