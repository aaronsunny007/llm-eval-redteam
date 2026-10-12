"""Turn transcripts + judgements into numbers, a Markdown report, a chart, JUnit XML and a
CI gate decision."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

from llm_redteam import __version__
from llm_redteam.config import GateConfig, RunConfig
from llm_redteam.detectors import leaked_secrets
from llm_redteam.judge import JUDGE_VERSION
from llm_redteam.metrics import Rate, agreement, format_p, interpret_kappa, mcnemar_exact
from llm_redteam.runner import Suite
from llm_redteam.schema import CATEGORIES, OWASP, GoldLabel, Judgement, Transcript

PRIMARY = "hybrid"


def _index(js: list[Judgement]) -> dict[tuple[str, str], Judgement]:
    return {(j.defence, j.case_id): j for j in js}


def summarise(
    cfg: RunConfig,
    suite: Suite,
    transcripts: list[Transcript],
    judgements: dict[str, list[Judgement]],
    gold: list[GoldLabel] | None = None,
) -> dict:
    primary = _index(judgements[PRIMARY])
    attack_ids = [a.id for a in suite.attacks]
    benign_ids = [b.id for b in suite.benign]
    cat_of = {a.id: a.category for a in suite.attacks}
    by_def: dict[str, dict[str, Transcript]] = defaultdict(dict)
    for t in transcripts:
        by_def[t.defence][t.case_id] = t

    defences: dict[str, dict] = {}
    outcomes: dict[str, list[bool]] = {}
    for d in cfg.defences:
        ts = by_def.get(d, {})
        succ = [bool(primary[(d, cid)].attack_success) for cid in attack_ids if (d, cid) in primary]
        outcomes[d] = succ
        per_cat = {}
        for cat in CATEGORIES:
            ids = [cid for cid in attack_ids if cat_of[cid] == cat and (d, cid) in primary]
            if ids:
                k = sum(bool(primary[(d, cid)].attack_success) for cid in ids)
                per_cat[cat] = Rate(k, len(ids)).as_dict()
        refusals = [bool(primary[(d, b)].refused) for b in benign_ids if (d, b) in primary]
        leaks = sum(
            1 for cid, t in ts.items()
            if cid in cat_of and leaked_secrets(t.response, suite.scenario.secrets)
        )  # fmt: skip
        lat = [t.latency_s for t in ts.values()]
        blocks: dict[str, int] = defaultdict(int)
        for t in ts.values():
            if t.blocked_by:
                blocks[f"{t.kind}:{t.blocked_by}"] += 1
        defences[d] = {
            "attack_success": Rate(sum(succ), len(succ)).as_dict(),
            "by_category": per_cat,
            "benign_refusal": Rate(sum(refusals), len(refusals)).as_dict(),
            "secret_leaks": leaks,
            "mean_latency_s": round(sum(lat) / len(lat), 2) if lat else 0.0,
            "guard_blocks": dict(blocks),
        }

    comparisons = {}
    if "none" in outcomes:
        for d in cfg.defences:
            if d != "none" and len(outcomes[d]) == len(outcomes["none"]):
                comparisons[d] = mcnemar_exact(outcomes["none"], outcomes[d])

    judge_eval = {}
    if gold:
        gold_map = {g.case_id: g.attack_success for g in gold}
        for name, js in judgements.items():
            idx = _index(js)
            ids = [cid for cid in attack_ids if cid in gold_map and ("none", cid) in idx]
            if not ids:
                continue
            ag = agreement([bool(idx[("none", c)].attack_success) for c in ids],
                           [gold_map[c] for c in ids])  # fmt: skip
            judge_eval[name] = {
                **ag.as_dict(),
                "kappa_band": interpret_kappa(ag.kappa),
                "disagreements": [
                    c for c in ids if bool(idx[("none", c)].attack_success) != gold_map[c]
                ],
                "judge_id": js[0].judge if js else name,
            }
        changed = [
            g.case_id for g in gold if g.suggested is not None and g.suggested != g.attack_success
        ]
        judge_eval["_gold"] = {
            "n": len(gold),
            "labellers": sorted({g.labeller for g in gold}),
            "attack_success_rate": Rate(sum(gold_map.values()), len(gold_map)).as_dict(),
            "suggestions_overridden": changed,
        }

    return {
        "name": cfg.name,
        "version": __version__,
        "scenario": suite.scenario.name,
        "target": cfg.target.model if cfg.target.type == "chat" else {"url": cfg.target.url},
        "guard_model": cfg.guard_model or cfg.target.model,
        "judge_model": cfg.judge.model,
        "judge_version": JUDGE_VERSION,
        "n_attacks": len(attack_ids),
        "n_benign": len(benign_ids),
        "defences": defences,
        "vs_baseline": comparisons,
        "judge_agreement": judge_eval,
    }


# ------------------------------------------------------------------------------- gate


@dataclass
class GateResult:
    passed: bool
    checks: list[tuple[str, bool, str]]


def evaluate_gate(summary: dict, gate: GateConfig) -> GateResult:
    d = summary["defences"][gate.defence]
    checks: list[tuple[str, bool, str]] = []
    n = d["attack_success"]["n"]
    checks.append(("attacks evaluated", n >= gate.min_attacks, f"{n} (min {gate.min_attacks})"))
    if gate.max_attack_success_rate is not None:
        r = d["attack_success"]["rate"]
        checks.append(("attack success rate", r <= gate.max_attack_success_rate,
                       f"{r:.1%} (max {gate.max_attack_success_rate:.1%})"))  # fmt: skip
    for cat, mx in gate.max_category_success_rate.items():
        r = d["by_category"].get(cat, {}).get("rate", 0.0)
        checks.append((f"{cat} success rate", r <= mx, f"{r:.1%} (max {mx:.1%})"))
    if gate.max_refusal_rate is not None and d["benign_refusal"]["n"]:
        r = d["benign_refusal"]["rate"]
        checks.append(("benign refusal rate", r <= gate.max_refusal_rate,
                       f"{r:.1%} (max {gate.max_refusal_rate:.1%})"))  # fmt: skip
    if gate.max_secret_leaks is not None:
        n = d["secret_leaks"]
        checks.append(
            ("secret leaks", n <= gate.max_secret_leaks, f"{n} (max {gate.max_secret_leaks})")
        )
    return GateResult(all(ok for _, ok, _ in checks), checks)


# ----------------------------------------------------------------------------- render


def _pct(r: dict) -> str:
    lo, hi = r["ci95"]
    return f"{r['rate']:.0%} <sub>[{lo:.0%}–{hi:.0%}]</sub>"


def render_markdown(summary: dict, gate: GateResult | None = None) -> str:
    L: list[str] = []
    L.append(f"# Red-team report — {summary['name']}\n")
    tgt = summary["target"]
    L.append(f"`llm-redteam {summary['version']}` · scenario **{summary['scenario']}** · "
             f"target `{tgt}` · judge `{summary['judge_model'] or 'detector-only'}` "
             f"(prompt v{summary.get('judge_version', '?')}) · "
             f"{summary['n_attacks']} attacks, {summary['n_benign']} benign controls\n")  # fmt: skip
    if gate:
        L.append(f"## CI gate: {'✅ PASSED' if gate.passed else '❌ FAILED'}\n")
        L.append("| Check | Result | Value |\n|---|---|---|")
        L += [f"| {n} | {'✅' if ok else '❌'} | {v} |" for n, ok, v in gate.checks]
        L.append("")

    L.append("## Defences\n")
    L.append("Attack success rate (ASR, lower is better) and benign refusal rate (lower is better), "
             "with Wilson 95% intervals. *p* is an exact McNemar test against no defence.\n")  # fmt: skip
    L.append(
        "| Defence | ASR | Benign refused | Secret leaks | Fixed / regressed | *p* | Latency |"
    )
    L.append("|---|---|---|---|---|---|---|")
    for d, s in summary["defences"].items():
        cmp = summary["vs_baseline"].get(d)
        fr = f"{cmp['fixed']} / {cmp['regressed']}" if cmp else "—"
        p = format_p(cmp["p_value"]) if cmp else "—"
        br = _pct(s["benign_refusal"]) if s["benign_refusal"]["n"] else "—"
        L.append(f"| `{d}` | {_pct(s['attack_success'])} | {br} | {s['secret_leaks']} | {fr} | {p} "
                 f"| {s['mean_latency_s']:.1f}s |")  # fmt: skip
    L.append("")

    L.append("## Attack success by category\n")
    defs = list(summary["defences"])
    L.append("| Category | OWASP | " + " | ".join(f"`{d}`" for d in defs) + " |")
    L.append("|---|---|" + "---|" * len(defs))
    for cat in CATEGORIES:
        cells = []
        for d in defs:
            r = summary["defences"][d]["by_category"].get(cat)
            cells.append(f"{r['k']}/{r['n']}" if r else "—")
        L.append(f"| {cat} | {OWASP[cat]} | " + " | ".join(cells) + " |")
    L.append("")

    ja = summary.get("judge_agreement") or {}
    if ja:
        g = ja.get("_gold", {})
        L.append("## Judge validation\n")
        L.append(f"Judges vs. {g.get('n')} gold labels on the undefended responses "
                 f"(labeller(s): {', '.join(g.get('labellers', []))}).\n")  # fmt: skip
        L.append("| Judge | Accuracy | Precision | Recall | F1 | Cohen's κ |")
        L.append("|---|---|---|---|---|---|")
        for name in ("hybrid", "llm", "keyword"):
            if name in ja:
                a = ja[name]
                L.append(f"| `{name}` | {a['accuracy']:.0%} | {a['precision']:.0%} | {a['recall']:.0%} "
                         f"| {a['f1']:.2f} | {a['kappa']:.2f} ({a['kappa_band']}) |")  # fmt: skip
        L.append("")
    return "\n".join(L)


def render_svg(summary: dict) -> str:
    """Grouped horizontal bars: ASR and benign refusal per defence, with CI whiskers."""
    defs = list(summary["defences"].items())
    row_h, top, left, width = 46, 56, 150, 420
    h = top + row_h * len(defs) + 40
    w = left + width + 80
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        f'font-family="Inter,Segoe UI,Helvetica,Arial,sans-serif" font-size="13">',
        "<style>text{fill:#334155}.mut{fill:#64748b}.grid{stroke:#e2e8f0}"
        "@media (prefers-color-scheme:dark){text{fill:#e2e8f0}.mut{fill:#94a3b8}.grid{stroke:#334155}}"
        "</style>",
        f'<text x="{left}" y="22" font-weight="600" font-size="15">Attack success vs. over-refusal by defence</text>',
        f'<rect x="{left}" y="32" width="12" height="12" rx="2" fill="#e11d48"/>'
        f'<text x="{left + 18}" y="42" class="mut">attack success rate</text>'
        f'<rect x="{left + 160}" y="32" width="12" height="12" rx="2" fill="#0ea5e9"/>'
        f'<text x="{left + 178}" y="42" class="mut">benign refusal rate</text>',
    ]
    for pct in (0, 25, 50, 75, 100):
        x = left + width * pct / 100
        out.append(f'<line x1="{x}" y1="{top - 4}" x2="{x}" y2="{h - 34}" class="grid"/>')
        out.append(f'<text x="{x}" y="{h - 18}" text-anchor="middle" class="mut">{pct}%</text>')
    for i, (name, s) in enumerate(defs):
        y = top + i * row_h
        out.append(f'<text x="{left - 10}" y="{y + 22}" text-anchor="end">{escape(name)}</text>')
        for j, (key, colour) in enumerate(
            (("attack_success", "#e11d48"), ("benign_refusal", "#0ea5e9"))
        ):
            r = s[key]
            if not r["n"]:
                continue
            by = y + 4 + j * 17
            bw = width * r["rate"]
            lo, hi = (width * c for c in r["ci95"])
            out.append(
                f'<rect x="{left}" y="{by}" width="{bw:.1f}" height="14" rx="3" fill="{colour}"/>'
            )
            out.append(f'<line x1="{left + lo:.1f}" y1="{by + 7}" x2="{left + hi:.1f}" y2="{by + 7}" '
                       f'stroke="{colour}" stroke-opacity=".55" stroke-width="2"/>')  # fmt: skip
            out.append(f'<text x="{left + max(bw, hi) + 6:.1f}" y="{by + 11}" class="mut" font-size="11">'
                       f'{r["rate"]:.0%}</text>')  # fmt: skip
    out.append("</svg>")
    return "\n".join(out)


def render_junit(summary: dict, suite: Suite, judgements: list[Judgement], defence: str,
                 gate: GateResult) -> str:  # fmt: skip
    """One testcase per attack/benign case for the gated defence, plus the gate checks."""
    idx = _index(judgements)
    cases: list[str] = []
    failures = 0
    for a in suite.attacks:
        j = idx.get((defence, a.id))
        if j is None:
            continue
        name = f"{a.id} {a.category}/{a.technique}"
        if j.attack_success:
            failures += 1
            cases.append(f'<testcase classname="attacks.{a.category}" name="{escape(name)}">'
                         f'<failure message="attack succeeded">{escape(j.rationale)}</failure></testcase>')  # fmt: skip
        else:
            cases.append(f'<testcase classname="attacks.{a.category}" name="{escape(name)}"/>')
    for n, ok, v in gate.checks:
        if not ok:
            failures += 1
        body = "" if ok else f'<failure message="{escape(v)}"/>'
        cases.append(f'<testcase classname="gate" name="{escape(n)}">{body}</testcase>')
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="llm-redteam:{escape(summary["name"])}" tests="{len(cases)}" '
        f'failures="{failures}">\n' + "\n".join(cases) + "\n</testsuite>\n"
    )


def write_reports(out: Path, summary: dict, md: str) -> None:
    from llm_redteam.io import dump_json

    dump_json(out / "summary.json", summary)
    (out / "report.md").write_text(md, encoding="utf-8")
    (out / "chart.svg").write_text(render_svg(summary), encoding="utf-8")
