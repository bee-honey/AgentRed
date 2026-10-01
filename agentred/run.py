"""End-to-end runner.

Wires the pieces together: build the target agent, run a scenario, evaluate the
trace against its invariant, report the result — across one or more scenarios.

Backends:
  --backend anthropic   real Claude (needs ANTHROPIC_API_KEY)
  --backend openai      real OpenAI (needs OPENAI_API_KEY)
  --backend scripted    offline demo: a naive agent (FAIL) vs a careful one (PASS)

Options:
  --scenario {egress,authz,approval,poisoning,all}
                                  which scenario(s) to run (default: all)
  --transport {inprocess,mcp}     run tools in-process, or over a real MCP
                                  boundary with a recording proxy
  --trials N                      run each target N times and report a rate
  -v / --verbose                  print full tool-call arguments
  --compare "spec,..."            compare several backend:model targets in a table
  --attacks CORPUS                also run each scenario with every attack template
                                  in a published corpus (e.g. agentdojo, or a JSON
                                  path) and report an attack x target table
  --report [DIR]                  write report.json + report.html (every trial's
                                  trace and findings) to DIR (default: agentred-report)
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .adapters import InProcessToolProvider, MCPToolProvider, ToolProvider
from .agent import AgentRun, TargetAgent
from .attacks import builtin_corpora, load_corpus, scenario_variants
from .env import load_dotenv
from .judge import Verdict, evaluate_scenario
from .models import Model, ModelTurn, ScriptedModel, ToolUse
from .report import Report
from .scenario import SCENARIOS, Scenario
from .stats import format_ci, format_rate, pairwise_lines

DEFAULT_COMPARE = ("scripted:naive", "scripted:careful", "openai:gpt-4o", "openai:gpt-4o-mini")

_REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_SERVER = str(_REPO_ROOT / "targets" / "mcp_servers" / "tools_server.py")


def make_provider(transport: str, scenario: Scenario) -> ToolProvider:
    """Build a fresh ToolProvider offering the scenario's tools."""
    if scenario.server_command:  # a third-party server: always over MCP, never trusted
        from .scan import untrusted_server_provider  # noqa: PLC0415

        return untrusted_server_provider(scenario.server_command)
    if transport == "mcp":
        cmd = [sys.executable, TOOLS_SERVER, *scenario.tools]
        for tool, description in scenario.description_overrides.items():
            cmd += ["--description", tool, description]
        return MCPToolProvider(cmd, cwd=str(_REPO_ROOT))
    return InProcessToolProvider(scenario.tools, scenario.description_overrides)


def _scripted_from_calls(
    calls: tuple[dict, ...], opening: str, closing: str = "Done."
) -> ScriptedModel:
    tool_uses = [
        ToolUse(id=f"tu_{i}", name=c["tool"], input=c["input"]) for i, c in enumerate(calls, 1)
    ]
    turns = []
    if tool_uses:
        turns.append(ModelTurn(text=opening, tool_uses=tool_uses))
    turns.append(ModelTurn(text=closing))
    return ScriptedModel(turns)


def build_model(spec: str, scenario: Scenario) -> Model:
    """Turn a `backend:model` spec into a Model, scenario-aware for scripted."""
    backend, _, model_id = spec.partition(":")
    backend, model_id = backend.strip().lower(), model_id.strip()

    if backend == "scripted":
        if model_id == "careful":
            return _scripted_from_calls(scenario.careful_calls, "Handling the request.")
        return _scripted_from_calls(scenario.naive_calls, "Following the attached instructions.")
    if backend == "openai":
        from .models import OpenAIModel  # noqa: PLC0415

        return OpenAIModel(model_id) if model_id else OpenAIModel()
    if backend == "anthropic":
        from .models import AnthropicModel  # noqa: PLC0415

        return AnthropicModel(model_id) if model_id else AnthropicModel()
    raise ValueError(f"unknown backend in spec {spec!r}")


def evaluate(
    scenario: Scenario, model: Model, provider: ToolProvider | None = None
) -> tuple[AgentRun, Verdict]:
    provider = provider or InProcessToolProvider(scenario.tools, scenario.description_overrides)
    agent = TargetAgent(model=model, system_prompt=scenario.system_prompt, tools=provider)
    run = agent.run(scenario.task)
    verdict = evaluate_scenario(run.trace, scenario)
    return run, verdict


@dataclass
class TrialSummary:
    label: str
    runs: list[AgentRun] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list)

    @property
    def trials(self) -> int:
        return len(self.verdicts)

    @property
    def violations(self) -> int:
        return sum(1 for v in self.verdicts if not v.passed)

    @property
    def rate(self) -> float:
        return self.violations / self.trials if self.trials else 0.0


def run_trials(
    scenario: Scenario,
    spec: str,
    trials: int,
    transport: str = "inprocess",
    report: Report | None = None,
) -> TrialSummary:
    summary = TrialSummary(label=spec)
    for _ in range(trials):
        model = build_model(spec, scenario)  # fresh model each trial (scripted replays reset)
        provider = make_provider(transport, scenario)  # fresh provider/trace (+ MCP subprocess)
        try:
            run, verdict = evaluate(scenario, model, provider)
        finally:
            provider.close()
        summary.runs.append(run)
        summary.verdicts.append(verdict)
    if report is not None:
        report.add(scenario, summary)
    return summary


# ---------- formatting ----------


def _trace_lines(run: AgentRun, verbose: bool) -> list[str]:
    lines: list[str] = ["Trace (recorded tool calls):"]
    if not run.trace.calls:
        lines.append("  (no tool calls)")
    for call in run.trace.calls:
        key = next((k for k in ("to", "user", "order_id") if k in call.args), None)
        arg = f"{key}={call.args.get(key)!r}" if key else ""
        lines.append(f"  span {call.span_id}: {call.name}({arg})")
        if verbose:
            for k, v in call.args.items():
                lines.append(f"      {k}: {v!r}")
    return lines


def _header(scenario: Scenario, label: str) -> list[str]:
    return [
        "=" * 64,
        f"AgentRed — {label}",
        "=" * 64,
        f"Scenario : {scenario.id}  ({scenario.category})",
        f"Invariant: {scenario.invariant}",
        "",
    ]


def format_report(
    label: str, scenario: Scenario, run: AgentRun, verdict: Verdict, verbose: bool = False
) -> str:
    lines = [*_header(scenario, label), *_trace_lines(run, verbose), "", f"VERDICT: {verdict.label}"]
    for f in verdict.findings:
        lines.append(f"  - [{f.invariant}] span {f.span_id}: {f.reason}")
    lines.append("=" * 64)
    return "\n".join(lines)


def format_trials(scenario: Scenario, summary: TrialSummary, verbose: bool) -> str:
    lines = _header(scenario, f"{summary.label} — {summary.trials} trial(s)")
    for i, (run, v) in enumerate(zip(summary.runs, summary.verdicts), start=1):
        lines.append(f"trial {i}: {v.label}")
        if verbose or not v.passed:
            lines += ["  " + ln for ln in _trace_lines(run, verbose)]
            for f in v.findings:
                lines.append(f"  - [{f.invariant}] span {f.span_id}: {f.reason}")
    lines += [
        "",
        f"VIOLATION RATE: {format_rate(summary.violations, summary.trials)}",
        "=" * 64,
    ]
    return "\n".join(lines)


def format_comparison(scenario: Scenario, summaries: list[TrialSummary], skipped: dict) -> str:
    lines = [
        *_header(scenario, "model comparison"),
        f"{'target':<28}{'trials':>7}{'viol':>6}{'rate':>7}{'95% CI':>12}",
        "-" * 60,
    ]
    for s in summaries:
        lines.append(
            f"{s.label:<28}{s.trials:>7}{s.violations:>6}{s.rate:>7.0%}"
            f"{format_ci(s.violations, s.trials):>12}"
        )
    for spec, why in skipped.items():
        short = why if len(why) < 30 else why[:27] + "..."
        lines.append(f"{spec:<28}{'—':>7}{'—':>6}{'skipped':>8}  ({short})")
    if pairs := pairwise_lines([(s.label, s.violations, s.trials) for s in summaries]):
        lines += ["", *pairs]
    lines.append("=" * 64)
    return "\n".join(lines)


def format_attack_matrix(
    scenario: Scenario,
    source: str,
    rows: dict[str, dict[str, TrialSummary]],
    targets: list[str],
    skipped: dict[str, str],
) -> str:
    """Rows are attacks, columns are targets, cells are violations/trials."""
    width = max(12, *(len(t) + 2 for t in targets))
    lines = [
        *_header(scenario, f"attack corpus: {source} ({len(rows)} attacks incl. handwritten)"),
        f"{'attack':<26}" + "".join(f"{t:>{width}}" for t in targets),
        "-" * (26 + width * len(targets)),
    ]
    for attack, cells in rows.items():
        lines.append(
            f"{attack:<26}"
            + "".join(f"{cells[t].violations}/{cells[t].trials}".rjust(width) for t in targets)
        )
    lines.append("-" * (26 + width * len(targets)))
    counts = [
        (t, sum(rows[a][t].violations for a in rows), sum(rows[a][t].trials for a in rows))
        for t in targets
    ]
    lines.append(
        f"{'total':<26}" + "".join(f"{k}/{n} ({k / n:.0%})".rjust(width) for _, k, n in counts)
    )
    lines.append(f"{'95% CI':<26}" + "".join(format_ci(k, n).rjust(width) for _, k, n in counts))
    if pairs := pairwise_lines(counts):
        lines += ["", *pairs]
    for spec, why in skipped.items():
        lines.append(f"skipped {spec}: {why}")
    lines.append("=" * 64)
    return "\n".join(lines)


def _targets(args: argparse.Namespace) -> list[str]:
    if args.compare is not None:
        if args.compare == "__default__":
            return list(DEFAULT_COMPARE)
        return [s.strip() for s in args.compare.split(",") if s.strip()]
    if args.backend in ("anthropic", "openai"):
        return [f"{args.backend}:{args.model}" if args.model else args.backend]
    return ["scripted:naive", "scripted:careful"]


def _run_attack_matrix(scenario: Scenario, args: argparse.Namespace, report: Report | None) -> int:
    attacks = load_corpus(args.attacks)
    variants = scenario_variants(scenario, attacks)
    targets, skipped = _targets(args), {}
    rows: dict[str, dict[str, TrialSummary]] = {v.attack: {} for v in variants}
    for spec in targets:
        try:
            for variant in variants:
                rows[variant.attack][spec] = run_trials(
                    variant, spec, args.trials, args.transport, report
                )
        except (RuntimeError, ValueError) as e:
            skipped[spec] = str(e)
    ran = [t for t in targets if t not in skipped]
    print(format_attack_matrix(scenario, attacks[0].source, rows, ran, skipped))
    return 0


# ---------- entrypoint ----------


def _run_one_scenario(
    scenario: Scenario, args: argparse.Namespace, report: Report | None = None
) -> int:
    if args.attacks:
        return _run_attack_matrix(scenario, args, report)

    # comparison mode
    if args.compare is not None:
        specs = _targets(args)
        summaries: list[TrialSummary] = []
        skipped: dict[str, str] = {}
        for spec in specs:
            try:
                summaries.append(run_trials(scenario, spec, args.trials, args.transport, report))
            except (RuntimeError, ValueError) as e:
                skipped[spec] = str(e)
        print(format_comparison(scenario, summaries, skipped))
        return 0

    # real single backend
    if args.backend in ("anthropic", "openai"):
        spec = f"{args.backend}:{args.model}" if args.model else args.backend
        summary = run_trials(scenario, spec, args.trials, args.transport, report)
        if args.trials > 1:
            print(format_trials(scenario, summary, args.verbose))
        else:
            print(
                format_report(
                    f"real agent ({args.backend})",
                    scenario,
                    summary.runs[0],
                    summary.verdicts[0],
                    args.verbose,
                )
            )
        return 0 if summary.violations == 0 else 1

    # offline scripted demo: same harness + evaluator, two behaviours
    rc = 0
    for label, spec in (("naive agent", "scripted:naive"), ("careful agent", "scripted:careful")):
        summary = run_trials(scenario, spec, 1, args.transport, report)
        run, verdict = summary.runs[0], summary.verdicts[0]
        print(format_report(label, scenario, run, verdict, args.verbose))
        print()
        rc |= 0 if verdict.passed else 0  # demo always exits 0
    return rc


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["scan"]:
        from .scan import scan_main  # noqa: PLC0415

        return scan_main(argv[1:])

    parser = argparse.ArgumentParser(description="Run AgentRed scenarios.")
    parser.add_argument("--backend", choices=["scripted", "anthropic", "openai"], default="scripted")
    parser.add_argument("--model", default=None, help="override the backend's default model id")
    parser.add_argument(
        "--scenario", choices=[*SCENARIOS.keys(), "all"], default="all", help="scenario(s) to run"
    )
    parser.add_argument("--trials", type=int, default=1, help="run N times and report a rate")
    parser.add_argument("-v", "--verbose", action="store_true", help="print full tool-call args")
    parser.add_argument(
        "--transport", choices=["inprocess", "mcp"], default="inprocess",
        help="run tools in-process, or over a real MCP boundary with a recording proxy",
    )
    parser.add_argument(
        "--compare", nargs="?", const="__default__", default=None,
        help="comma-separated backend:model specs to compare (default: a preset set)",
    )
    parser.add_argument(
        "--attacks", default=None, metavar="CORPUS",
        help=f"run every attack template in a corpus ({', '.join(builtin_corpora())} or a JSON path)",
    )
    parser.add_argument(
        "--report", nargs="?", const="agentred-report", default=None, metavar="DIR",
        help="write report.json + report.html with every trial's trace (default dir: agentred-report)",
    )
    args = parser.parse_args(argv)

    load_dotenv()  # pick up keys from a local .env (real env vars still win)

    selected = (
        list(SCENARIOS.values()) if args.scenario == "all" else [SCENARIOS[args.scenario]]
    )
    report = Report() if args.report else None
    rc = 0
    for scenario in selected:
        rc |= _run_one_scenario(scenario, args, report)
    if report is not None:
        json_path, html_path = report.write(args.report)
        print(f"Report: {html_path}  (data: {json_path})")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
