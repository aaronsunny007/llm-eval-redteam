"""Typed records shared by every stage of the pipeline.

Everything that crosses a file boundary (attack sets, run transcripts, judgements,
human labels) is one of these models, so a malformed row fails loudly at load time
instead of silently skewing a metric.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Category = Literal[
    "prompt_injection",
    "indirect_injection",
    "system_prompt_leak",
    "jailbreak",
    "data_exfiltration",
]
CATEGORIES: tuple[str, ...] = Category.__args__  # type: ignore[attr-defined]

# OWASP Top 10 for LLM Applications (2025) mapping, used in reports.
OWASP = {
    "prompt_injection": "LLM01:2025 Prompt Injection",
    "indirect_injection": "LLM01:2025 Prompt Injection (indirect)",
    "system_prompt_leak": "LLM07:2025 System Prompt Leakage",
    "jailbreak": "LLM01:2025 Prompt Injection (jailbreak)",
    "data_exfiltration": "LLM02:2025 Sensitive Information Disclosure",
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Attack(_Strict):
    """One adversarial test case."""

    id: str = Field(pattern=r"^[A-Z]{2,4}-\d{3}$")
    category: Category
    technique: str
    prompt: str = Field(min_length=1)
    context: list[str] = Field(
        default_factory=list,
        description="Retrieved documents shown to the model as untrusted context (RAG).",
    )
    goal: str = Field(min_length=1, description="What the attacker wants; success criterion.")
    success_markers: list[str] = Field(
        default_factory=list,
        description="Strings whose presence in a response proves the attack succeeded.",
    )
    severity: Literal["low", "medium", "high"] = "medium"

    @field_validator("success_markers")
    @classmethod
    def _markers_not_blank(cls, v: list[str]) -> list[str]:
        if any(not m.strip() for m in v):
            raise ValueError("success_markers must not contain blank strings")
        return v


class BenignPrompt(_Strict):
    """A legitimate request, used to measure over-refusal caused by defences."""

    id: str = Field(pattern=r"^BN-\d{3}$")
    prompt: str = Field(min_length=1)
    context: list[str] = Field(default_factory=list)
    note: str = ""


class Scenario(_Strict):
    """The application under test: its system prompt and the secrets it must protect."""

    name: str
    system_prompt: str
    secrets: list[str] = Field(
        default_factory=list,
        description="Protected strings (canaries, fake account data). Any leak is a failure.",
    )
    refusal_message: str = "I can't help with that request."


Kind = Literal["attack", "benign"]


class Transcript(_Strict):
    """What the system under test said for one case under one defence configuration."""

    case_id: str
    kind: Kind
    category: str
    defence: str
    response: str
    blocked_by: str | None = None
    latency_s: float = 0.0


class Judgement(_Strict):
    """A judge's decision about one transcript.

    For attacks, ``attack_success`` is set; for benign prompts, ``refused`` is set.
    """

    case_id: str
    kind: Kind
    defence: str
    judge: str
    attack_success: bool | None = None
    refused: bool | None = None
    method: str = Field(description="detector | llm | keyword | guard")
    rationale: str = ""


class GoldLabel(_Strict):
    """A human reference label for an undefended attack response."""

    case_id: str
    attack_success: bool
    labeller: str
    suggested: bool | None = Field(
        default=None, description="Pre-filled suggestion shown to the labeller, kept for audit."
    )
    note: str = ""
