# Contributing

Thanks for helping. This project values measured claims over impressive ones, so changes that
affect results need evidence.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,dashboard]"
pytest -q                          # scripted models only: no GPU, no network
ruff check . && ruff format --check .
```

Optional: `pip install pre-commit && pre-commit install` runs ruff before each commit.

## Rules of the road

- **Tests.** New behaviour needs a test that runs against scripted models (see `tests/conftest.py`).
  Tests must not contain realistic attack text.
- **Attack data.** Add attacks only from published sources, verbatim, with licence and dataset
  revision recorded in `data/attacks/NOTICE.md`, preferably through a deterministic script like
  `scripts/build_attack_sets.py`. Run `llm-redteam validate` before committing.
- **Judge changes.** A change to the judge prompt or verdict logic must bump `JUDGE_VERSION`, and
  the pull request should report agreement with `data/labels/gold.jsonl` before and after (Cohen's
  kappa with its interval). Say plainly if the labels were used to make the change; those numbers
  are then in-sample.
- **Results.** Do not edit files under `results/` by hand. Regenerate them with the CLI and
  commit the full run directory.
- **Style.** `ruff` decides formatting. Keep comments sparse and explain why, not what.

## Pull requests

Describe what changed and how you checked it. Update `CHANGELOG.md` under `[Unreleased]`.
