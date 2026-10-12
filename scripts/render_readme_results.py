"""Fill the README results block from results/<run>/summary.json.

    python scripts/render_readme_results.py results/finassist-mistral

Replaces the text between the RESULTS markers in README.md so every number in the README
comes straight from the run's summary.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from llm_redteam.metrics import format_p

START, END = "<!-- RESULTS:START -->", "<!-- RESULTS:END -->"


def pct(r: dict) -> str:
    lo, hi = r["ci95"]
    return f"{r['rate']:.0%} ({r['k']}/{r['n']}) [{lo:.0%}-{hi:.0%}]"


def render(run: Path) -> str:
    s = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    out = [
        f"Run `{s['name']}`: {s['n_attacks']} attacks, {s['n_benign']} benign controls. "
        f"Target `{s['target']['model']}` (Ollama), judge `{s['judge_model']['model']}`, "
        f"judge prompt v{s.get('judge_version', '?')}. 95% Wilson intervals in brackets.",
        "",
        "| Defence | Attack success | Benign refused | Secret leaks | Fixed / regressed | McNemar p |",
        "|---|---|---|---|---|---|",
    ]
    for d, v in s["defences"].items():
        c = s["vs_baseline"].get(d)
        fr = f"{c['fixed']} / {c['regressed']}" if c else "-"
        p = format_p(c["p_value"]) if c else "-"
        out.append(
            f"| `{d}` | {pct(v['attack_success'])} | {pct(v['benign_refusal'])} "
            f"| {v['secret_leaks']} | {fr} | {p} |"
        )
    cats = [
        c
        for c in ("prompt_injection", "indirect_injection")
        if any(c in v["by_category"] for v in s["defences"].values())
    ]
    out += [
        "",
        "| Category (attacks that succeeded) | "
        + " | ".join(f"`{d}`" for d in s["defences"])
        + " |",
        "|---|" + "---|" * len(s["defences"]),
    ]
    for c in cats:
        cells = []
        for v in s["defences"].values():
            r = v["by_category"].get(c)
            cells.append(f"{r['k']}/{r['n']}" if r else "-")
        out.append(f"| {c} | " + " | ".join(cells) + " |")
    ja = s.get("judge_agreement") or {}
    if ja:
        g = ja["_gold"]
        out += [
            "",
            f"Judge agreement with {g['n']} reference labels written by "
            f"{', '.join(f'`{x}`' for x in g['labellers'])} on the undefended responses:",
            "",
            "| Judge | Accuracy | Precision | Recall | F1 | Cohen's kappa |",
            "|---|---|---|---|---|---|",
        ]
        for name in ("hybrid", "llm", "keyword"):
            if name in ja:
                a = ja[name]
                out.append(
                    f"| `{name}` | {a['accuracy']:.0%} | {a['precision']:.0%} | {a['recall']:.0%} "
                    f"| {a['f1']:.2f} | {a['kappa']:.2f} ({a['kappa_band']}) |"
                )
    return "\n".join(out)


def main() -> None:
    run = Path(sys.argv[1])
    readme = Path(__file__).resolve().parents[1] / "README.md"
    text = readme.read_text(encoding="utf-8")
    head, rest = text.split(START, 1)
    _, tail = rest.split(END, 1)
    readme.write_text(f"{head}{START}\n{render(run)}\n{END}{tail}", encoding="utf-8", newline="\n")
    print(f"updated {readme}")


if __name__ == "__main__":
    main()
