"""Streamlit dashboard: results explorer + gold-labelling tool.

    llm-redteam dashboard            # or: streamlit run dashboard/app.py

The labelling page deliberately hides every judge verdict, so human labels are not
anchored on the judge they are used to validate.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from llm_redteam.io import load_attacks, read_jsonl, write_jsonl
from llm_redteam.schema import GoldLabel, Judgement, Transcript

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
DATA = ROOT / "data"
GOLD = DATA / "labels" / "human.jsonl"  # blind human labels; the AI labels live in gold.jsonl
SUGGESTIONS = DATA / "labels" / "suggestions.jsonl"

st.set_page_config(page_title="LLM Red-Team", page_icon="🛡️", layout="wide")


def runs() -> list[Path]:
    return sorted(p for p in RESULTS.glob("*") if (p / "transcripts.jsonl").exists())


@st.cache_data
def load_run(run_dir: str):
    d = Path(run_dir)
    ts = read_jsonl(d / "transcripts.jsonl", Transcript)
    js = {}
    for f in d.glob("judgements.*.jsonl"):
        js[f.stem.split(".", 1)[1]] = read_jsonl(f, Judgement)
    summary = (
        json.loads((d / "summary.json").read_text()) if (d / "summary.json").exists() else None
    )
    return ts, js, summary


def page_results() -> None:
    st.title("🛡️ Red-team results")
    available = runs()
    if not available:
        st.info("No runs yet. Run `llm-redteam run configs/benchmark.yaml`.")
        return
    run = st.sidebar.selectbox("Run", available, format_func=lambda p: p.name)
    ts, js, summary = load_run(str(run))

    if summary:
        cols = st.columns(len(summary["defences"]))
        base = summary["defences"].get("none", {}).get("attack_success", {}).get("rate")
        for col, (d, s) in zip(cols, summary["defences"].items(), strict=True):
            r = s["attack_success"]["rate"]
            delta = None if base is None or d == "none" else f"{(r - base) * 100:+.0f} pts"
            col.metric(d, f"{r:.0%}", delta, delta_color="inverse", help="attack success rate")
        chart = run / "chart.svg"
        if chart.exists():
            st.image(str(chart), use_container_width=True)
        if (run / "report.md").exists():
            with st.expander("Full report"):
                st.markdown((run / "report.md").read_text(encoding="utf-8"), unsafe_allow_html=True)

    judge = st.sidebar.selectbox(
        "Judge", sorted(js), index=sorted(js).index("hybrid") if "hybrid" in js else 0
    )
    jidx = {(j.defence, j.case_id): j for j in js.get(judge, [])}
    rows = []
    for t in ts:
        j = jidx.get((t.defence, t.case_id))
        verdict = None
        if j is not None:
            verdict = j.attack_success if t.kind == "attack" else j.refused
        rows.append({"case": t.case_id, "kind": t.kind, "category": t.category,
                     "defence": t.defence, "flagged": verdict, "blocked_by": t.blocked_by,
                     "latency_s": t.latency_s, "method": j.method if j else None})  # fmt: skip
    df = pd.DataFrame(rows)
    kind = st.sidebar.multiselect(
        "Kind", sorted(df.kind.unique()), default=sorted(df.kind.unique())
    )
    defs = st.sidebar.multiselect(
        "Defence", sorted(df.defence.unique()), default=sorted(df.defence.unique())
    )
    only = st.sidebar.checkbox("Only flagged (attack succeeded / benign refused)")
    view = df[df.kind.isin(kind) & df.defence.isin(defs)]
    if only:
        view = view[view.flagged == True]  # noqa: E712
    st.subheader(f"Transcripts ({len(view)})")
    st.dataframe(view, use_container_width=True, hide_index=True)

    tmap = {(t.defence, t.case_id): t for t in ts}
    pick = st.selectbox("Inspect", [f"{r.defence} / {r.case}" for r in view.itertuples()])
    if pick:
        d, cid = pick.split(" / ")
        t, j = tmap[(d, cid)], jidx.get((d, cid))
        st.markdown(
            f"**Response** ({t.latency_s:.1f}s{', blocked by ' + t.blocked_by if t.blocked_by else ''})"
        )
        st.code(t.response, language=None, wrap_lines=True)
        if j:
            st.markdown(f"**{judge} judge** · `{j.method}` · {j.rationale}")


def page_label() -> None:
    st.title("🏷️ Gold labelling")
    st.caption(
        "Label whether each **undefended** attack succeeded. Judge verdicts are hidden on "
        "purpose. The rubric is in docs/labelling-guide.md."
    )
    available = runs()
    if not available:
        st.info("Run the benchmark first so there are responses to label.")
        return
    run = st.sidebar.selectbox("Run", available, format_func=lambda p: p.name, key="lrun")
    labeller = st.sidebar.text_input("Your name / initials", key="labeller")
    ts, _, _ = load_run(str(run))
    attacks = {a.id: a for a in load_attacks([DATA / "attacks"])}
    items = [t for t in ts if t.defence == "none" and t.kind == "attack" and t.case_id in attacks]
    if not items:
        st.warning("No undefended attack transcripts in this run.")
        return

    gold = {g.case_id: g for g in read_jsonl(GOLD, GoldLabel)} if GOLD.exists() else {}
    sugg = (
        {g.case_id: g for g in read_jsonl(SUGGESTIONS, GoldLabel)} if SUGGESTIONS.exists() else {}
    )
    st.sidebar.progress(sum(i.case_id in gold for i in items) / len(items),
                        text=f"{sum(i.case_id in gold for i in items)}/{len(items)} labelled")  # fmt: skip

    if "idx" not in st.session_state:
        st.session_state.idx = next((n for n, i in enumerate(items) if i.case_id not in gold), 0)
    idx = st.session_state.idx
    t = items[idx]
    a = attacks[t.case_id]

    st.subheader(f"{idx + 1}/{len(items)} · {a.id} · {a.category} · {a.technique}")
    st.markdown(f"**Attacker's goal:** {a.goal}")
    with st.expander("Attack prompt", expanded=True):
        st.code(a.prompt, language=None, wrap_lines=True)
    if a.context:
        with st.expander("Retrieved documents"):
            for doc in a.context:
                st.code(doc, language=None, wrap_lines=True)
    st.markdown("**Model response**")
    st.code(t.response, language=None, wrap_lines=True)

    prior = gold.get(t.case_id) or sugg.get(t.case_id)
    default = None if prior is None else (0 if prior.attack_success else 1)
    choice = st.radio("Did the attack succeed?", ["Yes — attack succeeded", "No — model was safe"],
                      index=default, horizontal=True, key=f"c-{t.case_id}")  # fmt: skip
    note = st.text_input("Note (optional)", value=gold[t.case_id].note if t.case_id in gold else "",
                         key=f"n-{t.case_id}")  # fmt: skip

    c1, c2, c3 = st.columns(3)
    if c1.button("← Previous", disabled=idx == 0):
        st.session_state.idx -= 1
        st.rerun()
    if c2.button("Save & next →", type="primary", disabled=choice is None or not labeller):
        gold[t.case_id] = GoldLabel(
            case_id=t.case_id,
            attack_success=choice.startswith("Yes"),
            labeller=labeller,
            suggested=sugg[t.case_id].attack_success if t.case_id in sugg else None,
            note=note,
        )
        write_jsonl(GOLD, [gold[k] for k in sorted(gold)])
        st.session_state.idx = min(idx + 1, len(items) - 1)
        st.rerun()
    if c3.button("Skip →", disabled=idx == len(items) - 1):
        st.session_state.idx += 1
        st.rerun()
    if not labeller:
        st.caption("Enter your name in the sidebar to save labels.")
    st.caption(
        f"Saved to {GOLD.relative_to(ROOT)} · {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC"
    )


nav = st.navigation([st.Page(page_results, title="Results", icon="📊"),
                     st.Page(page_label, title="Label", icon="🏷️")])  # fmt: skip
nav.run()
