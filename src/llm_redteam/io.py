"""Loading and saving the JSONL / YAML files the harness runs on."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from llm_redteam.schema import Attack, BenignPrompt, Scenario

M = TypeVar("M", bound=BaseModel)


class DataError(ValueError):
    """Raised when a data file is malformed. The message names the file and line."""


def iter_jsonl(path: Path, model: type[M]) -> Iterator[M]:
    with Path(path).open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                yield model.model_validate_json(line)
            except ValidationError as exc:
                raise DataError(f"{path}:{lineno}: {exc}") from exc


def read_jsonl(path: Path, model: type[M]) -> list[M]:
    return list(iter_jsonl(path, model))


def write_jsonl(path: Path, rows: Iterable[BaseModel]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(row.model_dump_json(exclude_none=False) + "\n")


def append_jsonl(path: Path, row: BaseModel) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(row.model_dump_json() + "\n")


def _expand(paths: Iterable[str | Path], base: Path) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        p = (base / p) if not Path(p).is_absolute() else Path(p)
        out.extend(sorted(p.glob("*.jsonl")) if p.is_dir() else [p])
    return out


def load_attacks(paths: Iterable[str | Path], base: Path = Path(".")) -> list[Attack]:
    attacks: list[Attack] = []
    for f in _expand(paths, base):
        attacks.extend(read_jsonl(f, Attack))
    _check_unique(a.id for a in attacks)
    return attacks


def load_benign(paths: Iterable[str | Path], base: Path = Path(".")) -> list[BenignPrompt]:
    rows: list[BenignPrompt] = []
    for f in _expand(paths, base):
        rows.extend(read_jsonl(f, BenignPrompt))
    _check_unique(b.id for b in rows)
    return rows


def load_scenario(path: Path) -> Scenario:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    try:
        scenario = Scenario.model_validate(data)
    except ValidationError as exc:
        raise DataError(f"{path}: {exc}") from exc
    missing = [s for s in scenario.secrets if s not in scenario.system_prompt]
    if missing:
        raise DataError(f"{path}: secrets not present in system_prompt: {missing}")
    return scenario


def _check_unique(ids: Iterable[str]) -> None:
    seen: set[str] = set()
    dupes = sorted({i for i in ids if i in seen or seen.add(i)})  # type: ignore[func-returns-value]
    if dupes:
        raise DataError(f"duplicate case ids: {dupes}")


def dump_json(path: Path, obj: object) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
