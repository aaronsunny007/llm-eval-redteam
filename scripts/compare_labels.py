"""Compare human labels with the AI labels, and each judge with the human labels.

    python scripts/compare_labels.py results/finassist-mistral > paper/human_stats.json

Reads data/labels/human.jsonl (written by the dashboard's Label page, blind to the AI labels and
to every judge verdict) and data/labels/gold.jsonl (the AI labels). Prints JSON with:
  * human-vs-AI agreement (Cohen's kappa with a bootstrap interval) and every disagreement;
  * for each judge, agreement with the human labels, overall and split by how a case is decided.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from paper_stats import JUDGED, LEAK, agreement_block, bootstrap_kappa, read

from llm_redteam.metrics import agreement


def main(run: Path) -> None:
    human = {g["case_id"]: g for g in read(Path("data/labels/human.jsonl"))}
    ai = {g["case_id"]: g for g in read(Path("data/labels/gold.jsonl"))}
    common = sorted(set(human) & set(ai))
    if not common:
        raise SystemExit("no human labels yet: label some cases on the dashboard's Label page")

    h = [human[c]["attack_success"] for c in common]
    a = [ai[c]["attack_success"] for c in common]
    ag = agreement(h, a)
    out: dict = {
        "labelled_by_human": len(human),
        "compared_with_ai": len(common),
        "human_vs_ai": {
            "raw_agreement": round((ag.tp + ag.tn) / len(common), 3),
            "kappa": round(ag.kappa, 3),
            "kappa_ci95": bootstrap_kappa(h, a),
            "human_success_rate": round(sum(h) / len(h), 3),
            "ai_success_rate": round(sum(a) / len(a), 3),
        },
        "disagreements": [
            {
                "case": c,
                "human": human[c]["attack_success"],
                "ai": ai[c]["attack_success"],
                "human_note": human[c].get("note", ""),
                "ai_note": ai[c].get("note", ""),
            }
            for c in common
            if human[c]["attack_success"] != ai[c]["attack_success"]
        ],
    }

    gold = {c: human[c]["attack_success"] for c in common}
    judges = {}
    for f in sorted(run.glob("judgements.*.jsonl")):
        name = f.stem.split(".", 1)[1]
        undefended = {
            r["case_id"]: r["attack_success"]
            for r in read(f)
            if r["defence"] == "none" and r["kind"] == "attack"
        }
        if all(c in undefended for c in gold):
            judges[name] = {
                "all": agreement_block(undefended, gold, LEAK + JUDGED + ("PI", "II")),
                "leak_categories": agreement_block(undefended, gold, LEAK),
                "judgement_categories": agreement_block(undefended, gold, JUDGED),
            }
    out["judge_vs_human"] = judges
    json.dump(out, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main(Path(sys.argv[1]))
