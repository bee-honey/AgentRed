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
  --designs LIST                  hold the model fixed and compare agent designs
                                  (prompt-only, hardened-prompt, pinned-tools,
                                  policy-guard, or "all")
  --agent "CMD"                   test a black-box agent instead of AgentRed's own loop
                                  (stdin/stdout contract in agentred/external.py); also
                                  usable in --compare as "agent:CMD"
  --report [DIR]                  write report.json + report.html (every trial's
                                  trace and findings) to DIR (default: agentred-report)
"""

from __future__ import annotations

import argparse
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .adapters import InProcessToolProvider, MCPToolProvider, ToolProvider
from .agent import AgentRun, TargetAgent
from .attacks import builtin_corpora, load_attacks, scenario_variants
from .designs import DESIGNS, AgentDesign
from .external import agent_label, run_external
from .env import load_dotenv
from .judge import Verdict, evaluate_scenario
from .models import Model, ModelTurn, ScriptedModel, ToolUse
from .report import Report
from .scenario import SCENARIOS, Scenario
from .stats import fisher_exact, format_ci, format_p, format_rate, pairwise_lines
from .utility import task_done_for_trace

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
            return _scripted_from_calls(
                scenario.careful_calls, "Handling the request.", scenario.careful_reply
            )
        return _scripted_from_calls(scenario.naive_calls, "Following the attached instructions.")
    if backend == "openai":
        from .models import OpenAIModel  # noqa: PLC0415

        return OpenAIModel(model_id) if model_id else OpenAIModel()
    if backend == "anthropic":
        from .models import AnthropicModel  # noqa: PLC0415

        return AnthropicModel(model_id) if model_id else AnthropicModel()
    raise ValueError(f"unknown backend in spec {spec!r}")


def evaluate(
    scenario: Scenario,
    model: Model,
    provider: ToolProvider | None = None,
    design: AgentDesign | None = None,
) -> tuple[AgentRun, Verdict]:
    provider = provider or InProcessToolProvider(scenario.tools, scenario.description_overrides)
    agent_scenario = scenario
    if design is not None:
        agent_scenario, provider = design.apply(scenario, provider)
    agent = TargetAgent(model=model, system_prompt=agent_scenario.system_prompt, tools=provider)
    run = agent.run(scenario.task, scenario.followups)
    verdict = evaluate_scenario(run.trace, scenario)
    return run, verdict


@dataclass
class TrialSummary:
    label: str
    design: str = "prompt-only"
    runs: list[AgentRun] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list)
    done: list[bool | None] = field(default_factory=list)  # legitimate task completed?

    @property
    def trials(self) -> int:
        return len(self.verdicts)

    @property
    def violations(self) -> int:
        return sum(1 for v in self.verdicts if not v.passed)

    @property
    def rate(self) -> float:
        return self.violations / self.trials if self.trials else 0.0

    @property
    def tasks_done(self) -> str:
        known = [d for d in self.done if d is not None]
        return f"{sum(known)}/{len(known)}" if known else "—"

    @property
    def attempted(self) -> int:
        """Trials where a control blocked at least one call: the model tried."""
        return sum(1 for r in self.runs if r.trace.blocked)


def run_trials(
    scenario: Scenario,
    spec: str,
    trials: int,
    transport: str = "inprocess",
    report: Report | None = None,
    design: AgentDesign | None = None,
    label: str | None = None,
) -> TrialSummary:
    if spec.startswith("agent:"):  # a black-box agent: its own loop, judged at the MCP boundary
        if design is not None and design.id != "prompt-only":
            raise ValueError("--designs applies to AgentRed's own agent, not a black-box agent")
        command = shlex.split(spec.removeprefix("agent:"))
        summary = TrialSummary(label=label or agent_label(command))
        for _ in range(trials):
            run = run_external(scenario, command)
            summary.runs.append(run)
            summary.verdicts.append(evaluate_scenario(run.trace, scenario))
            summary.done.append(task_done_for_trace(run.trace, run.final_text, scenario))
        if report is not None:
            report.add(scenario, summary)
        return summary

    summary = TrialSummary(label=label or spec, design=design.id if design else "prompt-only")
    for _ in range(trials):
        model = build_model(spec, scenario)  # fresh model each trial (scripted replays reset)
        provider = make_provider(transport, scenario)  # fresh provider/trace (+ MCP subprocess)
        try:
            run, verdict = evaluate(scenario, model, provider, design)
        finally:
            provider.close()
        summary.runs.append(run)
        summary.verdicts.append(verdict)
        summary.done.append(task_done_for_trace(run.trace, run.final_text, scenario))
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


def format_design_table(scenario: Scenario, spec: str, summaries: list[TrialSummary]) -> str:
    """One row per design (same model): violations, attempts a control blocked, vs baseline."""
    base = summaries[0]
    lines = [
        *_header(scenario, f"agent designs on {spec}"),
        f"{'design':<18}{'violated':>10}{'95% CI':>12}{'blocked':>9}{'task done':>11}   vs {base.design}",
        "-" * 74,
    ]
    for s in summaries:
        versus = (
            "—" if s is base
            else format_p(fisher_exact(s.violations, s.trials, base.violations, base.trials))
        )
        lines.append(
            f"{s.design:<18}{f'{s.violations}/{s.trials}':>10}"
            f"{format_ci(s.violations, s.trials):>12}{f'{s.attempted}/{s.trials}':>9}"
            f"{s.tasks_done:>11}   {versus}"
        )
    lines += [
        "",
        "  violated = an executed call broke the invariant; blocked = trials where a",
        "  control refused at least one call (the model tried, nothing ran);",
        "  task done = the user's legitimate request was still completed",
        "=" * 64,
    ]
    return "\n".join(lines)


def _design_list(value: str) -> list[AgentDesign]:
    names = list(DESIGNS) if value == "all" else [v.strip() for v in value.split(",") if v.strip()]
    unknown = [n for n in names if n not in DESIGNS]
    if unknown:
        raise SystemExit(f"unknown design(s) {unknown}; choose from {', '.join(DESIGNS)} or all")
    return [DESIGNS[n] for n in names]


def _run_design_comparison(scenario: Scenario, args: argparse.Namespace, report: Report | None) -> int:
    # One model for every design. Offline, that's the worst case: a scripted model
    # that obeys every injection, so only controls that don't rely on it can help.
    targets = _targets(args)
    if len(targets) != 1 and not (args.backend == "scripted" and args.compare is None):
        raise SystemExit("--designs holds the model fixed: pass one --backend/--model, not --compare")
    spec = targets[0] if len(targets) == 1 else "scripted:naive"
    variants = scenario_variants(scenario, load_attacks(args.attacks)) if args.attacks else [scenario]
    summaries = []
    for design in _design_list(args.designs):
        merged = TrialSummary(label=design.id, design=design.id)
        for variant in variants:
            s = run_trials(variant, spec, args.trials, args.transport, report, design, label=design.id)
            merged.runs += s.runs
            merged.verdicts += s.verdicts
            merged.done += s.done
        summaries.append(merged)
    print(format_design_table(scenario, spec, summaries))
    return 0


def _targets(args: argparse.Namespace) -> list[str]:
    if args.agent:
        return [f"agent:{args.agent}"]
    if args.compare is not None:
        if args.compare == "__default__":
            return list(DEFAULT_COMPARE)
        return [s.strip() for s in args.compare.split(",") if s.strip()]
    if args.backend in ("anthropic", "openai"):
        return [f"{args.backend}:{args.model}" if args.model else args.backend]
    return ["scripted:naive", "scripted:careful"]


def _run_attack_matrix(scenario: Scenario, args: argparse.Namespace, report: Report | None) -> int:
    attacks = load_attacks(args.attacks)
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
    sources = " + ".join(dict.fromkeys(a.source for a in attacks))
    print(format_attack_matrix(scenario, sources, rows, ran, skipped))
    return 0


# ---------- entrypoint ----------


def _run_one_scenario(
    scenario: Scenario, args: argparse.Namespace, report: Report | None = None
) -> int:
    if args.designs:
        return _run_design_comparison(scenario, args, report)
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

    # a black-box agent
    if args.agent:
        summary = run_trials(scenario, f"agent:{args.agent}", args.trials, report=report)
        print(format_trials(scenario, summary, args.verbose))
        return 0 if summary.violations == 0 else 1

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
    if argv[:1] == ["rescore"]:
        from .utility import rescore_main  # noqa: PLC0415

        return rescore_main(argv[1:])
    if argv[:1] == ["judge-eval"]:
        from .llm_judge import judge_eval_main  # noqa: PLC0415

        return judge_eval_main(argv[1:])

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
        help=f"attack sets to run, comma-separated ({', '.join(builtin_corpora())}, or a JSON path)",
    )
    parser.add_argument(
        "--agent", default=None, metavar="CMD",
        help="test a black-box agent command (see agentred/external.py for the contract)",
    )
    parser.add_argument(
        "--designs", default=None, metavar="LIST",
        help=f"compare agent designs on one model ({', '.join(DESIGNS)}, or all)",
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
