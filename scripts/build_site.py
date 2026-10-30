"""Build the static results site (one HTML file plus the paper PDF) for GitHub Pages.

    python scripts/build_site.py            # writes site/index.html

Everything shown comes from committed files under results/, paper/ and data/attacks/. Responses to
the jailbreak cases (replies to harmful requests) are withheld from the page; their verdicts and
aggregate numbers are still shown.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results" / "finassist-mistral"
REP = ROOT / "results" / "finassist-qwen2.5-7b"
OUT = ROOT / "site"
REPO = "https://github.com/aaronsunny007/llm-eval-redteam"

CAT_NAMES = {
    "prompt_injection": "Prompt injection",
    "indirect_injection": "Indirect injection",
    "system_prompt_leak": "System-prompt leak",
    "data_exfiltration": "Data exfiltration",
    "jailbreak": "Jailbreak",
}
DEF_NAMES = {
    "none": "None",
    "hardened_prompt": "Hardened prompt",
    "input_guard": "Input guard",
    "output_guard": "Output guard",
    "layered": "Layered",
}


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def clip(text: str, n: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else text[:n].rstrip() + " ..."


def pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def rate_cell(r: dict) -> str:
    lo, hi = r["ci95"]
    return f"{pct(r['rate'])} <span class='ci'>[{pct(lo)}&ndash;{pct(hi)}]</span> <span class='n'>({r['k']}/{r['n']})</span>"


def build_rows() -> list[dict]:
    attacks = {}
    for f in (ROOT / "data" / "attacks").glob("*.jsonl"):
        for a in read_jsonl(f):
            attacks[a["id"]] = a
    benign = {b["id"]: b for b in read_jsonl(ROOT / "data" / "benign" / "benign.jsonl")}
    gold = {
        g["case_id"]: g["attack_success"]
        for g in read_jsonl(ROOT / "data" / "labels" / "gold.jsonl")
    }
    judged = {(j["defence"], j["case_id"]): j for j in read_jsonl(RUN / "judgements.hybrid.jsonl")}
    rows = []
    for t in read_jsonl(RUN / "transcripts.jsonl"):
        cid, d = t["case_id"], t["defence"]
        j = judged.get((d, cid), {})
        case = attacks.get(cid) or benign.get(cid) or {}
        withheld = t["category"] == "jailbreak"
        rows.append(
            {
                "id": cid,
                "cat": t["category"],
                "kind": t["kind"],
                "def": d,
                "prompt": clip(case.get("prompt", ""), 420),
                "context": clip("\n---\n".join(case.get("context", [])), 420),
                "response": "[withheld: this is a reply to a harmful request]"
                if withheld and t["kind"] == "attack"
                else clip(t["response"], 760),
                "blocked": t.get("blocked_by") or "",
                "verdict": j.get("attack_success") if t["kind"] == "attack" else j.get("refused"),
                "method": j.get("method", ""),
                "why": clip(j.get("rationale", ""), 260),
                "label": gold.get(cid) if d == "none" and t["kind"] == "attack" else None,
            }
        )
    return rows


def table_defences(s: dict) -> str:
    out = []
    for d, v in s["defences"].items():
        cmp = s["vs_baseline"].get(d)
        p = "&ndash;"
        if cmp:
            p = "&lt;0.0001" if cmp["p_value"] < 1e-4 else f"{cmp['p_value']:.3g}"
        out.append(
            f"<tr><th scope='row'>{DEF_NAMES[d]}</th><td>{rate_cell(v['attack_success'])}</td>"
            f"<td>{rate_cell(v['benign_refusal'])}</td><td>{v['secret_leaks']}</td><td>{p}</td></tr>"
        )
    return "\n".join(out)


def table_categories(s: dict) -> str:
    head = "".join(f"<th>{DEF_NAMES[d]}</th>" for d in s["defences"])
    body = []
    for c, name in CAT_NAMES.items():
        cells = []
        for v in s["defences"].values():
            r = v["by_category"].get(c)
            cells.append(f"<td>{r['k']}/{r['n']}</td>" if r else "<td>&ndash;</td>")
        body.append(f"<tr><th scope='row'>{name}</th>{''.join(cells)}</tr>")
    return f"<thead><tr><th></th>{head}</tr></thead><tbody>{''.join(body)}</tbody>"


def table_judge(stats: dict) -> str:
    rows = []
    labels = [
        ("hybrid", "all", "Hybrid judge, all cases"),
        ("hybrid", "leak_categories", "Hybrid, leak categories (deterministic detector decides)"),
        ("hybrid", "judgement_categories", "Hybrid, injection and jailbreak (LLM decides)"),
        ("llm", "all", "LLM judge alone, all cases"),
        ("keyword", "all", "Keyword baseline, all cases"),
    ]
    for judge, subset, label in labels:
        b = stats["judge_agreement"][judge][subset]
        lo, hi = b["kappa_ci95"] or [float("nan"), float("nan")]
        rows.append(
            f"<tr><th scope='row'>{label}</th><td>{b['n']}</td><td><b>{b['kappa']:.2f}</b> "
            f"<span class='ci'>[{lo:.2f}&ndash;{hi:.2f}]</span></td>"
            f"<td>{b['precision']:.2f}</td><td>{b['recall']:.2f}</td></tr>"
        )
    return "\n".join(rows)


def replication_table(s: dict, m: dict) -> str:
    rows = []
    for name, summ in (("Mistral 7B", m), ("Qwen 2.5 7B", s)):
        for d in ("none", "layered"):
            v = summ["defences"][d]
            rows.append(
                f"<tr><th scope='row'>{name}</th><td>{DEF_NAMES[d]}</td>"
                f"<td>{rate_cell(v['attack_success'])}</td><td>{rate_cell(v['benign_refusal'])}</td>"
                f"<td>{v['secret_leaks']}</td></tr>"
            )
    return "\n".join(rows)


TEMPLATE = (ROOT / "scripts" / "site_template.html").read_text(encoding="utf-8")


def main() -> None:
    s = json.loads((RUN / "summary.json").read_text(encoding="utf-8"))
    rep = json.loads((REP / "summary.json").read_text(encoding="utf-8"))
    stats = json.loads((ROOT / "paper" / "stats.json").read_text(encoding="utf-8"))
    rows = build_rows()
    chart = (RUN / "chart.svg").read_text(encoding="utf-8")
    d = s["defences"]
    values = {
        "REPO": REPO,
        "VERSION": s["version"],
        "ASR_NONE": pct(d["none"]["attack_success"]["rate"]),
        "ASR_LAYERED": pct(d["layered"]["attack_success"]["rate"]),
        "LEAKS_NONE": str(d["none"]["secret_leaks"]),
        "KAPPA_ALL": f"{stats['judge_agreement']['hybrid']['all']['kappa']:.2f}",
        "KAPPA_LLM": f"{stats['judge_agreement']['hybrid']['judgement_categories']['kappa']:.2f}",
        "N_ATTACKS": str(s["n_attacks"]),
        "TABLE_DEFENCES": table_defences(s),
        "TABLE_CATEGORIES": table_categories(s),
        "TABLE_JUDGE": table_judge(stats),
        "TABLE_REPLICATION": replication_table(rep, s),
        "CHART": chart,
        "DATA": json.dumps(rows, ensure_ascii=False).replace("</", "<\\/"),
    }
    html = TEMPLATE
    for key, val in values.items():
        html = html.replace("{{" + key + "}}", val)
    OUT.mkdir(exist_ok=True)
    (OUT / "index.html").write_text(html, encoding="utf-8", newline="\n")
    shutil.copy(ROOT / "paper" / "paper.pdf", OUT / "paper.pdf")
    print(f"wrote {OUT / 'index.html'} ({len(html) // 1024} KB, {len(rows)} transcripts)")


if __name__ == "__main__":
    main()
