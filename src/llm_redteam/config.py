"""Run configuration (one YAML file describes a whole benchmark or CI gate)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from llm_redteam.defences import PRESETS


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TargetConfig(_Strict):
    type: Literal["chat", "http"] = "chat"
    model: dict[str, Any] | None = None
    # http only
    url: str | None = None
    body: dict[str, Any] | None = None
    response_path: str = "answer"
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: float = 120.0

    @model_validator(mode="after")
    def _check(self) -> TargetConfig:
        if self.type == "chat" and not self.model:
            raise ValueError("chat target needs `model`")
        if self.type == "http" and not self.url:
            raise ValueError("http target needs `url`")
        return self


class JudgeConfig(_Strict):
    #: ``None`` → detector-only judging (no model needed; weaker, see README).
    model: dict[str, Any] | None = None


class GateConfig(_Strict):
    """Pass/fail thresholds for CI. Unset thresholds are not checked."""

    defence: str = "none"
    #: Fail if fewer attacks than this were evaluated (guards against an empty suite passing).
    min_attacks: int = 1
    max_attack_success_rate: float | None = None
    max_category_success_rate: dict[str, float] = Field(default_factory=dict)
    max_refusal_rate: float | None = None
    max_secret_leaks: int | None = 0


class RunConfig(_Strict):
    name: str
    scenario: Path
    attacks: list[Path]
    benign: list[Path] = Field(default_factory=list)
    target: TargetConfig
    guard_model: dict[str, Any] | None = None
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    defences: list[str] = Field(default_factory=lambda: ["none"])
    output_dir: Path
    gold_labels: Path | None = None
    gate: GateConfig = Field(default_factory=GateConfig)
    #: Directory relative paths are resolved against (default: the working directory).
    base_dir: Path = Path(".")

    @model_validator(mode="after")
    def _check(self) -> RunConfig:
        unknown = [d for d in self.defences if d not in PRESETS]
        if unknown:
            raise ValueError(f"unknown defences {unknown}; choose from {sorted(PRESETS)}")
        if self.gate.defence not in self.defences:
            raise ValueError(f"gate.defence {self.gate.defence!r} is not in defences")
        return self

    def path(self, p: Path | str) -> Path:
        """Resolve a path. ``builtin:attacks`` points at the data bundled with the package."""
        s = str(p).replace("\\", "/")
        if s.startswith("builtin:"):
            return builtin_data(s.removeprefix("builtin:"))
        p = Path(p)
        return p if p.is_absolute() else self.base_dir / p

    @property
    def out(self) -> Path:
        return self.path(self.output_dir)


def builtin_data(rel: str = "") -> Path:
    """Data shipped in the wheel (``llm_redteam/_data``) or, in a source checkout, ``data/``."""
    here = Path(__file__).resolve().parent
    for root in (here / "_data", here.parents[1] / "data"):
        if root.is_dir():
            return root / rel
    raise FileNotFoundError("bundled data not found; reinstall llm-redteam")


def load_config(path: Path, overrides: dict[str, Any] | None = None) -> RunConfig:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for dotted, value in (overrides or {}).items():
        node = data
        *parents, leaf = dotted.split(".")
        for key in parents:
            node = node.setdefault(key, {})
        node[leaf] = value
    return RunConfig.model_validate(data)
