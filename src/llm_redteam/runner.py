"""Generation and judging stages.

Both stages append one JSON line per finished item and skip items already on disk, so a
long run on a laptop GPU can be interrupted and resumed without losing work.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from llm_redteam.config import RunConfig
from llm_redteam.defences import PRESETS, Pipeline
from llm_redteam.io import append_jsonl, load_attacks, load_benign, load_scenario, read_jsonl
from llm_redteam.judge import HybridJudge, Judge, KeywordJudge, LLMJudge
from llm_redteam.models import (
    ChatModel,
    ChatTarget,
    HTTPTarget,
    Target,
    build_chat_model,
)
from llm_redteam.schema import Attack, BenignPrompt, Judgement, Scenario, Transcript

Progress = Callable[[str], None]


@dataclass
class Suite:
    scenario: Scenario
    attacks: list[Attack]
    benign: list[BenignPrompt]

    @property
    def attack_by_id(self) -> dict[str, Attack]:
        return {a.id: a for a in self.attacks}

    @property
    def benign_by_id(self) -> dict[str, BenignPrompt]:
        return {b.id: b for b in self.benign}


def load_suite(cfg: RunConfig) -> Suite:
    return Suite(
        scenario=load_scenario(cfg.path(cfg.scenario)),
        attacks=load_attacks([cfg.path(p) for p in cfg.attacks]),
        benign=load_benign([cfg.path(p) for p in cfg.benign]),
    )


def transcripts_path(cfg: RunConfig) -> Path:
    return cfg.out / "transcripts.jsonl"


def judgements_path(cfg: RunConfig, judge: str) -> Path:
    return cfg.out / f"judgements.{judge}.jsonl"


def build_target(cfg: RunConfig, scenario: Scenario, model: ChatModel | None = None) -> Target:
    t = cfg.target
    if t.type == "chat":
        return ChatTarget(model or build_chat_model(t.model or {}), scenario.system_prompt)
    return HTTPTarget(
        url=t.url or "", body=t.body, response_path=t.response_path,
        headers=t.headers, timeout=t.timeout,
    )  # fmt: skip


def build_guard_model(cfg: RunConfig, target_model: ChatModel | None) -> ChatModel | None:
    if cfg.guard_model:
        return build_chat_model(cfg.guard_model)
    return target_model


def generate(
    cfg: RunConfig,
    suite: Suite,
    *,
    target_model: ChatModel | None = None,
    guard_model: ChatModel | None = None,
    progress: Progress = lambda _: None,
) -> list[Transcript]:
    """Run every case through every configured defence. Resumable."""
    path = transcripts_path(cfg)
    done = (
        {(t.defence, t.case_id) for t in read_jsonl(path, Transcript)} if path.exists() else set()
    )

    if cfg.target.type == "chat" and target_model is None:
        target_model = build_chat_model(cfg.target.model or {})
    target = build_target(cfg, suite.scenario, target_model)
    guard = guard_model or build_guard_model(cfg, target_model)

    cases: list[tuple[str, str, str, str, list[str]]] = [
        (a.id, "attack", a.category, a.prompt, a.context) for a in suite.attacks
    ] + [(b.id, "benign", "benign", b.prompt, b.context) for b in suite.benign]

    for defence in cfg.defences:
        pipe = Pipeline(target, suite.scenario, PRESETS[defence], guard, name=defence)
        todo = [c for c in cases if (defence, c[0]) not in done]
        for i, (cid, kind, cat, prompt, ctx) in enumerate(todo, 1):
            t = pipe.respond(cid, kind, cat, prompt, ctx)
            append_jsonl(path, t)
            progress(f"[{defence}] {i}/{len(todo)} {cid} {t.latency_s:.1f}s"
                     + (f" blocked:{t.blocked_by}" if t.blocked_by else ""))  # fmt: skip
        if pipe.log:
            for entry in pipe.log:
                append_jsonl_dict(cfg.out / "guard_log.jsonl", {"defence": defence, **entry})
    return read_jsonl(path, Transcript)


def append_jsonl_dict(path: Path, row: dict) -> None:
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def build_judges(
    cfg: RunConfig, scenario: Scenario, judge_model: ChatModel | None = None
) -> dict[str, Judge]:
    """The judges a run uses: ``hybrid`` (primary), ``llm`` (ablation), ``keyword`` (baseline)."""
    if judge_model is None and cfg.judge.model:
        judge_model = build_chat_model(cfg.judge.model)
    llm = LLMJudge(judge_model, scenario) if judge_model else None
    judges: dict[str, Judge] = {"hybrid": HybridJudge(scenario, llm), "keyword": KeywordJudge()}
    if llm:
        judges["llm"] = llm
    return judges


def judge_all(
    cfg: RunConfig,
    suite: Suite,
    transcripts: list[Transcript],
    judges: dict[str, Judge],
    *,
    only_baseline_for: tuple[str, ...] = ("llm",),
    progress: Progress = lambda _: None,
) -> dict[str, list[Judgement]]:
    """Judge every transcript. The ``llm``-only ablation judge runs on the undefended
    baseline only (it is used to measure agreement with human labels, not to score)."""
    attacks, benign = suite.attack_by_id, suite.benign_by_id
    out: dict[str, list[Judgement]] = {}
    for name, judge in judges.items():
        path = judgements_path(cfg, name)
        previous = read_jsonl(path, Judgement) if path.exists() else []
        other = sorted({j.judge for j in previous} - {judge.name})
        if other:
            raise RuntimeError(
                f"{path} already holds verdicts from {other}, not {judge.name}. Resuming would "
                "mix judges: delete the file or use a new output_dir."
            )
        done = {(j.defence, j.case_id) for j in previous}
        todo = [
            t for t in transcripts
            if (t.defence, t.case_id) not in done
            and not (name in only_baseline_for and t.defence != "none")
            and (t.case_id in attacks or t.case_id in benign)
        ]  # fmt: skip
        for i, t in enumerate(todo, 1):
            j = (
                judge.judge_attack(attacks[t.case_id], t)
                if t.kind == "attack"
                else judge.judge_benign(benign[t.case_id], t)
            )
            append_jsonl(path, j)
            if name != "keyword":
                progress(f"[judge:{name}] {i}/{len(todo)} {t.defence}/{t.case_id}")
        out[name] = read_jsonl(path, Judgement)
    return out
