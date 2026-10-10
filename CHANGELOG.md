# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Installable package `llm-redteam` with a CLI: `run`, `ci`, `report`, `validate`, `dashboard`.
- Attack sets as versioned, schema-validated JSONL data files (`data/attacks/`), plus a
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
- Test suite against scripted models; CI on Python 3.10 and 3.12; action self-test.

### Removed
- FastAPI service, DeepEval dependency and the hallucination prototype.
- Committed `mlflow.db` and DeepEval telemetry files.
