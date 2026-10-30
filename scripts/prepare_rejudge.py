"""Copy the Mistral transcripts into the stronger-judge run directory so only judging is redone.

python scripts/prepare_rejudge.py
"""

from __future__ import annotations

import shutil
from pathlib import Path

SRC = Path("results/finassist-mistral")
DST = Path("results/finassist-mistral-gemini-judge")


def main() -> None:
    DST.mkdir(parents=True, exist_ok=True)
    for name in ("transcripts.jsonl", "guard_log.jsonl"):
        shutil.copy(SRC / name, DST / name)
    print(f"copied transcripts and guard log to {DST}; now run:")
    print(
        "  llm-redteam run configs/benchmark-gemini-judge.yaml --skip-generate "
        "--set judge.model.model=<model name>"
    )


if __name__ == "__main__":
    main()
