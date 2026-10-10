"""Command-line interface: ``llm-redteam run | ci | report | validate | dashboard``."""

from __future__ import annotations

import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console
from rich.table import Table

from llm_redteam import __version__
from llm_redteam.config import RunConfig, builtin_data, load_config
from llm_redteam.io import DataError, load_attacks, load_benign, load_scenario, read_jsonl
from llm_redteam.report import (
    PRIMARY,
    evaluate_gate,
    render_junit,
    render_markdown,
    summarise,
    write_reports,
)
from llm_redteam.runner import build_judges, generate, judge_all, load_suite, transcripts_path
from llm_redteam.schema import GoldLabel, Transcript

app = typer.Typer(add_completion=False, no_args_is_help=True, help=__doc__)
console = Console(stderr=True)

ConfigArg = Annotated[Path, typer.Argument(help="Run config YAML.", exists=True, dir_okay=False)]
SetOpt = Annotated[
    list[str] | None,
    typer.Option("--set", help="Override a config value, e.g. --set target.model.model=llama3.1"),
]


def _overrides(items: list[str] | None) -> dict:
    out = {}
    for item in items or []:
        key, _, raw = item.partition("=")
        out[key] = yaml.safe_load(raw)
    return out


def _load(config: Path, sets: list[str] | None) -> RunConfig:
    try:
        return load_config(config, _overrides(sets))
    except (DataError, ValueError) as exc:
        console.print(f"[red]config error:[/] {exc}")
        raise typer.Exit(2) from exc


def _execute(cfg: RunConfig, skip_generate: bool, log_mlflow: bool):
    suite = load_suite(cfg)
    console.print(
        f"[bold]{cfg.name}[/]: {len(suite.attacks)} attacks, {len(suite.benign)} benign, "
        f"defences={cfg.defences}"
    )
    progress = (
        (lambda m: console.print(f"  [dim]{m}[/]"))
        if sys.stderr.isatty() or os.getenv("CI")
        else (lambda m: None)
    )
    if skip_generate:
        transcripts = read_jsonl(transcripts_path(cfg), Transcript)
    else:
        transcripts = generate(cfg, suite, progress=progress)
    judgements = judge_all(
        cfg, suite, transcripts, build_judges(cfg, suite.scenario), progress=progress
    )
    gold = None
    if cfg.gold_labels and cfg.path(cfg.gold_labels).exists():
        gold = read_jsonl(cfg.path(cfg.gold_labels), GoldLabel)
    summary = summarise(cfg, suite, transcripts, judgements, gold)
    if log_mlflow:
        _log_mlflow(cfg, summary)
    return suite, judgements, summary


def _print_table(summary: dict) -> None:
    t = Table(title=f"{summary['name']} - attack success / benign refusal (95% CI)")
    for col in ("defence", "attack success", "benign refused", "leaks"):
        t.add_column(col)
    for d, s in summary["defences"].items():
        a, b = s["attack_success"], s["benign_refusal"]
        t.add_row(
            d,
            f"{a['rate']:.0%} [{a['ci95'][0]:.0%}-{a['ci95'][1]:.0%}] ({a['k']}/{a['n']})",
            f"{b['rate']:.0%} ({b['k']}/{b['n']})" if b["n"] else "-",
            str(s["secret_leaks"]),
        )
    Console().print(t)


def _log_mlflow(cfg: RunConfig, summary: dict) -> None:
    try:
        import mlflow
    except ImportError:
        console.print("[yellow]mlflow not installed; pip install 'llm-redteam[mlflow]'[/]")
        return
    mlflow.set_experiment("llm-redteam")
    for d, s in summary["defences"].items():
        with mlflow.start_run(run_name=f"{cfg.name}/{d}"):
            mlflow.log_params({"config": cfg.name, "defence": d, "target": str(summary["target"]),
                               "judge": str(summary["judge_model"])})  # fmt: skip
            mlflow.log_metric("attack_success_rate", s["attack_success"]["rate"])
            mlflow.log_metric("benign_refusal_rate", s["benign_refusal"]["rate"])
            mlflow.log_metric("secret_leaks", s["secret_leaks"])
            for cat, r in s["by_category"].items():
                mlflow.log_metric(f"asr_{cat}", r["rate"])
            mlflow.log_artifact(str(cfg.out / "report.md"))


@app.command()
def run(
    config: ConfigArg,
    set: SetOpt = None,  # noqa: A002
    skip_generate: Annotated[
        bool, typer.Option(help="Re-judge existing transcripts only.")
    ] = False,
    mlflow: Annotated[bool, typer.Option(help="Log results to MLflow.")] = False,
):
    """Generate responses, judge them and write the report (resumable)."""
    cfg = _load(config, set)
    _, _, summary = _execute(cfg, skip_generate, log_mlflow=False)
    write_reports(cfg.out, summary, render_markdown(summary))
    if mlflow:
        _log_mlflow(cfg, summary)
    _print_table(summary)
    console.print(f"report: {cfg.out / 'report.md'}")


@app.command()
def ci(
    config: ConfigArg,
    set: SetOpt = None,  # noqa: A002
    junit: Annotated[Path | None, typer.Option(help="Write JUnit XML here.")] = None,
):
    """Run the suite and enforce the config's gate. Exit code 1 if the gate fails."""
    cfg = _load(config, set)
    suite, judgements, summary = _execute(cfg, skip_generate=False, log_mlflow=False)
    gate = evaluate_gate(summary, cfg.gate)
    md = render_markdown(summary, gate)
    write_reports(cfg.out, summary, md)
    junit_path = junit or cfg.out / "junit.xml"
    junit_path.write_text(
        render_junit(summary, suite, judgements[PRIMARY], cfg.gate.defence, gate), encoding="utf-8"
    )
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(md + "\n")
    _print_table(summary)
    for name, ok, value in gate.checks:
        console.print(f"  {'[green]PASS[/]' if ok else '[red]FAIL[/]'} {name}: {value}")
    console.print("[bold green]gate passed[/]" if gate.passed else "[bold red]gate failed[/]")
    raise typer.Exit(0 if gate.passed else 1)


@app.command()
def report(config: ConfigArg, set: SetOpt = None):  # noqa: A002
    """Re-render the report from existing transcripts and judgements."""
    cfg = _load(config, set)
    _, _, summary = _execute(cfg, skip_generate=True, log_mlflow=False)
    write_reports(cfg.out, summary, render_markdown(summary))
    _print_table(summary)


@app.command()
def validate(
    data_dir: Annotated[
        Path | None, typer.Argument(help="Data directory (default: bundled).")
    ] = None,
):
    """Schema-check attack sets, benign sets and scenarios, and print coverage."""
    root = data_dir or builtin_data()
    try:
        attacks = load_attacks([root / "attacks"])
        benign = load_benign([root / "benign"]) if (root / "benign").exists() else []
        scenarios = [load_scenario(p) for p in sorted((root / "scenarios").glob("*.yaml"))]
    except DataError as exc:
        console.print(f"[red]invalid:[/] {exc}")
        raise typer.Exit(1) from exc
    t = Table(title=f"{root}")
    t.add_column("category")
    t.add_column("attacks", justify="right")
    t.add_column("techniques")
    for cat, n in sorted(Counter(a.category for a in attacks).items()):
        techs = sorted({a.technique for a in attacks if a.category == cat})
        t.add_row(cat, str(n), ", ".join(techs))
    Console().print(t)
    console.print(f"[green]ok[/]: {len(attacks)} attacks, {len(benign)} benign, "
                  f"{len(scenarios)} scenario(s)")  # fmt: skip


@app.command()
def dashboard(port: int = 8501):
    """Open the results explorer and labelling tool (needs the [dashboard] extra)."""
    app_path = Path(__file__).resolve().parents[2] / "dashboard" / "app.py"
    if not app_path.exists():
        console.print("[red]dashboard/app.py not found[/]; run from a source checkout.")
        raise typer.Exit(1)
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(app_path),
                    "--server.port", str(port)], check=False)  # fmt: skip


@app.callback(invoke_without_command=True)
def _version(
    version: Annotated[bool, typer.Option("--version", help="Show version.")] = False,
) -> None:
    if version:
        print(__version__)
        raise typer.Exit()
