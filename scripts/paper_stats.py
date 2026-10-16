"""Extra statistics for the paper, computed from a committed results directory.

    python scripts/paper_stats.py results/finassist-mistral > paper/stats.json

Adds what report.md does not show: bootstrap confidence intervals for judge agreement
(resampling cases), judge-vs-label agreement split by how a case is decided, and paired
McNemar comparisons between every pair of defences.
"""

from __future__ import annotations

import json
import random
import statistics
import sys
from itertools import combinations
from pathlib import Path

from llm_redteam.metrics import agreement, mcnemar_exact, wilson

SEED = 20261012
RESAMPLES = 10_000
LEAK = ("SL", "DX")
JUDGED = ("PI", "II", "JB")


def read(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def kappa(pred: list[bool], gold: list[bool]) -> float:
    return agreement(pred, gold).kappa


def bootstrap_kappa(pred: list[bool], gold: list[bool]) -> list[float]:
    rng = random.Random(SEED)
    n = len(pred)
    vals = []
    for _ in range(RESAMPLES):
        idx = [rng.randrange(n) for _ in range(n)]
        p, g = [pred[i] for i in idx], [gold[i] for i in idx]
        # kappa is undefined when the labels are all one class; skip those resamples
        if len(set(g)) < 2:
            continue
        vals.append(kappa(p, g))
    vals.sort()
    if not vals:
        return []
    return [round(vals[int(0.025 * len(vals))], 3), round(vals[int(0.975 * len(vals))], 3)]


def agreement_block(judge: dict, gold: dict, prefixes: tuple[str, ...]) -> dict:
    ids = sorted(c for c in gold if c[:2] in prefixes and c in judge)
    pred = [judge[c] for c in ids]
    true = [gold[c] for c in ids]
    a = agreement(pred, true)
    return {
        "n": len(ids),
        "tp": a.tp, "fp": a.fp, "fn": a.fn, "tn": a.tn,
        "accuracy": round(a.accuracy, 3),
        "precision": round(a.precision, 3),
        "recall": round(a.recall, 3),
        "kappa": round(a.kappa, 3),
        "kappa_ci95": bootstrap_kappa(pred, true),
    }  # fmt: skip


def main(run: Path, use_labels: bool = True) -> None:
    # The reference labels were written for the Mistral responses; for any other target they
    # do not apply, so pass --no-labels and only judged numbers are produced.
    gold = (
        {g["case_id"]: g["attack_success"] for g in read(Path("data/labels/gold.jsonl"))}
        if use_labels
        else {}
    )
    tr = read(run / "transcripts.jsonl")
    out: dict = {"run": run.name, "bootstrap_resamples": RESAMPLES, "seed": SEED}

    judges = {}
    for f in sorted(run.glob("judgements.*.jsonl")):
        judges[f.stem.split(".", 1)[1]] = read(f)

    # judge agreement, overall and by decision route (undefended responses only)
    agree = {}
    for name, rows in judges.items():
        und = {
            r["case_id"]: r["attack_success"]
            for r in rows
            if r["defence"] == "none" and r["kind"] == "attack"
        }
        if not gold or not all(c in und for c in gold):
            continue
        agree[name] = {
            "all": agreement_block(und, gold, LEAK + JUDGED + ("PI", "II")),
            "leak_categories": agreement_block(und, gold, LEAK),
            "judgement_categories": agreement_block(und, gold, JUDGED),
            "injection_only": agreement_block(und, gold, ("PI", "II")),
            "jailbreak_only": agreement_block(und, gold, ("JB",)),
        }
    out["judge_agreement"] = agree

    # undefended ASR: reference labels vs the hybrid judge, per category
    hyb = {
        (r["defence"], r["case_id"]): r["attack_success"]
        for r in judges.get("hybrid", [])
        if r["kind"] == "attack"
    }
    cats = {}
    case_ids = sorted({i for d, i in hyb if d == "none"})
    for c in ("PI", "II", "SL", "DX", "JB"):
        ids = [i for i in case_ids if i[:2] == c]
        cats[c] = {"n": len(ids), "judge": sum(hyb[("none", i)] for i in ids)}
        if gold:
            cats[c]["labels"] = sum(gold[i] for i in ids)
    k_judge = sum(hyb[("none", i)] for i in case_ids)
    out["undefended_asr"] = {
        "judge": {"k": k_judge, "n": len(case_ids), "wilson95": [round(x, 3) for x in wilson(k_judge, len(case_ids))]},
        "by_category": cats,
    }  # fmt: skip
    if gold:
        k_gold = sum(gold.values())
        out["undefended_asr"]["labels"] = {
            "k": k_gold, "n": len(gold), "wilson95": [round(x, 3) for x in wilson(k_gold, len(gold))],
        }  # fmt: skip

    # paired comparisons between every pair of defences (hybrid judge, attacks)
    defences = sorted({d for d, _ in hyb})
    ids = sorted({i for _, i in hyb})
    pairs = {}
    for a, b in combinations(defences, 2):
        xs = [hyb[(a, i)] for i in ids if (a, i) in hyb and (b, i) in hyb]
        ys = [hyb[(b, i)] for i in ids if (a, i) in hyb and (b, i) in hyb]
        r = mcnemar_exact(xs, ys)
        pairs[f"{a}_vs_{b}"] = {
            "a_only_succeeds": r["fixed"], "b_only_succeeds": r["regressed"],
            "p_value": r["p_value"],
        }  # fmt: skip
    out["pairwise_defences"] = pairs

    # latency per defence (median seconds over all cases)
    lat: dict[str, list[float]] = {}
    for t in tr:
        lat.setdefault(t["defence"], []).append(t["latency_s"])
    out["median_latency_s"] = {d: round(statistics.median(v), 1) for d, v in sorted(lat.items())}

    # how often the guards stopped a request, per defence (attacks and benign)
    blocked: dict[str, dict] = {}
    for t in tr:
        b = blocked.setdefault(t["defence"], {"attack": [0, 0], "benign": [0, 0]})
        b[t["kind"]][1] += 1
        b[t["kind"]][0] += bool(t.get("blocked_by"))
    out["guard_block_counts"] = blocked

    json.dump(out, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main(Path(sys.argv[1]), use_labels="--no-labels" not in sys.argv[2:])
