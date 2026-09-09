"""Command-line interface for the R-Sandbox research-security agent."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from r_sandbox.agent.orchestrator import AgentMode, RSandboxAgent
from r_sandbox.agent.reporter import ReportGenerator
from r_sandbox.models import AgentOutcome, SecurityVerdict


def _dashboard_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if not 0 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be in 0..65535")
    return port


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="r-sandbox",
        description="Analyze an untrusted research repository and preflight it in a least-authority sandbox.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    ui = subparsers.add_parser(
        "ui",
        help="Open the loopback-only local security workbench.",
    )
    ui.add_argument(
        "--port",
        type=_dashboard_port,
        default=8765,
        help="Loopback port (default: 8765; use 0 for an ephemeral port).",
    )
    ui.add_argument(
        "--no-open",
        action="store_true",
        help="Start the local UI without opening a browser.",
    )
    for name, help_text in (
        ("analyze", "Static repository understanding and an initial, explicitly inconclusive verdict."),
        ("dry-run", "Generate the project-specific sandbox command without executing repository code."),
        ("shadow", "Run an explicit Docker-isolated security preflight and observe behavior."),
    ):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("repository", type=Path)
        command.add_argument("--goal", required=True, help="Natural-language research objective.")
        command.add_argument("--output", type=Path, help="Dedicated writable artifact directory.")
        command.add_argument("--report", type=Path, help="Write .json or Markdown report to this path.")
        command.add_argument(
            "--image",
            default="python:3.11-slim",
            help=(
                "Container image reference; use an immutable sha256 digest for "
                "reproducible evidence (the default tag is mutable)."
            ),
        )
        command.add_argument(
            "--approve",
            action="append",
            default=[],
            metavar="REQUEST_ID",
            help="Approve one exact capability request; hard denials cannot be overridden.",
        )
        command.add_argument(
            "--allow-domain",
            action="append",
            default=[],
            metavar="HOSTNAME[:PORT]",
            help="Narrow network target. Shadow execution fails closed without an enforcing proxy adapter.",
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "ui":
        from r_sandbox.ui import serve_dashboard

        try:
            return serve_dashboard(
                port=args.port,
                open_browser=not args.no_open,
            )
        except (OSError, ValueError) as exc:
            print(f"r-sandbox: could not start local UI: {exc}", file=sys.stderr)
            return 2
    mode = {
        "analyze": AgentMode.ANALYZE,
        "dry-run": AgentMode.DRY_RUN,
        "shadow": AgentMode.SHADOW,
    }[args.command]
    try:
        repository = args.repository.resolve(strict=True)
        output = (
            args.output
            or repository.parent / f".{repository.name}-r-sandbox" / "output"
        ).resolve(strict=False)
        report = RSandboxAgent().run(
            repository,
            args.goal,
            output=output,
            mode=mode,
            image=args.image,
            approved_request_ids=frozenset(args.approve),
            network_allowlist=frozenset(args.allow_domain),
        )
    except (OSError, ValueError) as exc:
        print(f"r-sandbox: {exc}", file=sys.stderr)
        return 2

    renderer = ReportGenerator()
    rendered = renderer.json_text(report)
    if args.report:
        try:
            renderer.write(
                report,
                args.report,
                forbidden_roots=(repository, output),
            )
        except (OSError, ValueError) as exc:
            print(rendered)
            print(f"r-sandbox: could not write report: {exc}", file=sys.stderr)
            return 2
    print(rendered)
    return _exit_code(report.outcome, report.security_assessment.verdict, mode)


def _exit_code(outcome: AgentOutcome, verdict: SecurityVerdict, mode: AgentMode) -> int:
    """Make Shadow mode safe for CI/security-gate use."""

    if mode != AgentMode.SHADOW:
        return 1 if outcome in {AgentOutcome.FAILED, AgentOutcome.BLOCKED} else 0
    if outcome == AgentOutcome.SUCCEEDED and verdict == SecurityVerdict.SAFE:
        return 0
    if outcome in {AgentOutcome.FAILED, AgentOutcome.BLOCKED}:
        return 1
    if outcome in {AgentOutcome.RUNTIME_UNAVAILABLE, AgentOutcome.AWAITING_APPROVAL}:
        return 3
    if verdict == SecurityVerdict.INCONCLUSIVE:
        return 3
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
