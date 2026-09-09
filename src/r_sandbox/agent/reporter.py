"""Human- and machine-readable run reports."""

from __future__ import annotations

import json
import html
import os
from pathlib import Path
import uuid

from r_sandbox.models import AgentReport, canonical_agent_report


class ReportGenerator:
    def json_text(self, report: AgentReport) -> str:
        return json.dumps(
            report.to_dict(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )

    def markdown(self, report: AgentReport) -> str:
        report = canonical_agent_report(report)
        lines = [
            "# R-Sandbox execution report",
            "",
            "- Security gate: "
            + (
                "`not_evaluated`"
                if report.security_assessment is None
                else (
                    "`pass`"
                    if report.security_assessment.verdict.value == "safe"
                    else (
                        "`inconclusive`"
                        if report.security_assessment.verdict.value == "inconclusive"
                        else "`fail`"
                    )
                )
            ),
            f"- Workflow/execution outcome: `{report.outcome.value}`",
            f"- Goal: {_md_text(report.goal)}",
            f"- Repository: {_md_code(report.repository)}",
        ]
        if report.plan:
            lines.extend(["", "## Plan", "", _md_text(report.plan.summary)])
            for step in report.plan.steps:
                lines.append(
                    f"- {_md_code(json.dumps(step.argv, ensure_ascii=False))} — "
                    f"{_md_text(step.purpose)}"
                )
        if report.environment_plan:
            environment = report.environment_plan
            lines.extend(["", "## Project environment plan", ""])
            lines.append(f"- Runtime: {_md_code(environment.runtime)}")
            lines.append(f"- Image: {_md_code(environment.image)}")
            lines.append(f"- Digest-pinned image: `{environment.image_pinned}`")
            lines.append(f"- Readiness: `{environment.readiness.value}`")
            lines.append(f"- Declared dependencies: `{len(environment.dependencies)}`")
            for dependency in environment.dependencies:
                lines.append(
                    f"- {_md_code(dependency.name + dependency.specifier)} from "
                    f"{_md_code(dependency.source)}"
                )
            for warning in environment.warnings:
                lines.append(f"- Warning: {_md_text(warning)}")
        if report.profile:
            lines.extend(["", "## Repository evidence", ""])
            lines.append(f"- Files inventoried: `{len(report.profile.files)}`")
            lines.append(f"- Dependencies declared: `{len(report.profile.dependencies)}`")
            lines.append(f"- Static findings: `{len(report.profile.findings)}`")
            if report.profile.snapshot_digest:
                lines.append(
                    f"- Snapshot SHA-256: {_md_code(report.profile.snapshot_digest)}"
                )
            if report.profile.authorization_context:
                lines.append(
                    "- Authorization context: "
                    f"{_md_code(report.profile.authorization_context)}"
                )
            if report.profile.snapshot_omissions:
                lines.append(
                    f"- Paths withheld or skipped: `{len(report.profile.snapshot_omissions)}`"
                )
            for finding in report.profile.findings:
                lines.append(
                    f"- **{finding.risk.value}** "
                    f"{_md_code(f'{finding.category.value}:{finding.action}:{finding.target}')} "
                    f"— {_md_text(finding.reason)}"
                )
            if report.profile.warnings:
                lines.extend(["", "### Analysis coverage warnings", ""])
                lines.extend(
                    f"- {_md_text(warning)}" for warning in report.profile.warnings
                )
        if report.authorization:
            lines.extend(["", "## Authority decisions", ""])
            for item in report.authorization.decisions:
                req = item.request
                lines.append(
                    f"- **{item.decision.value}** {_md_code(req.request_id)} "
                    f"{_md_code(f'{req.category.value}:{req.action}:{req.target}')} "
                    f"— {_md_text(item.reason)}"
                )
        if report.execution:
            lines.extend(
                [
                    "",
                    "## Execution",
                    "",
                    f"- Exit code: `{report.execution.exit_code}`",
                    f"- Duration: `{report.execution.duration_seconds:.3f}s`",
                    "- Command preview (audit record; snapshot path may be expired): "
                    f"{_md_code(json.dumps(report.execution.command_preview, ensure_ascii=False))}",
                ]
            )
            if report.execution.events:
                lines.extend(["", "### Observed events", ""])
                for event in report.execution.events:
                    target_controlled = event.source.value == "target_telemetry"
                    event_type = (
                        "target_telemetry" if target_controlled else event.event_type
                    )
                    action = "reported_event" if target_controlled else event.action
                    target = (
                        "<target-controlled-content-omitted>"
                        if target_controlled
                        else event.target
                    )
                    detail = (
                        "Target-controlled content omitted from report."
                        if target_controlled
                        else event.detail
                    )
                    lines.append(
                        f"- {_md_code(event_type)} {_md_text(action)} "
                        f"{_md_code(target)}: "
                        f"{'allowed' if event.allowed else 'blocked'} — {_md_text(detail)}"
                    )
        if len(report.execution_history) > 1:
            lines.extend(["", "## Execution attempt history", ""])
            for index, result in enumerate(report.execution_history, start=1):
                lines.append(
                    f"- Attempt `{index}`: outcome `{result.status.value}`, "
                    f"exit `{result.exit_code}`, events `{len(result.events)}`"
                )
                for event in result.events:
                    target_controlled = event.source.value == "target_telemetry"
                    event_type = (
                        "target_telemetry" if target_controlled else event.event_type
                    )
                    action = "reported_event" if target_controlled else event.action
                    target = (
                        "<target-controlled-content-omitted>"
                        if target_controlled
                        else event.target
                    )
                    detail = (
                        "Target-controlled content omitted from report."
                        if target_controlled
                        else event.detail
                    )
                    lines.append(
                        f"  - {_md_code(event_type)} {_md_text(action)} "
                        f"{_md_code(target)}: "
                        f"{'allowed' if event.allowed else 'blocked'} — {_md_text(detail)}"
                    )
        if report.sandbox:
            lines.extend(
                [
                    "",
                    "## Sandbox",
                    "",
                    f"- Image: {_md_code(report.sandbox.image)}",
                    "- Source repository: "
                    f"{_md_code(report.sandbox.source_repository or report.repository)}",
                    "- Container source: sanitized snapshot mounted read-only at `/workspace`",
                    f"- Snapshot SHA-256: {_md_code(report.sandbox.snapshot_digest or 'unavailable')}",
                    f"- Fresh per-run output mount: {_md_code(report.sandbox.output)} (read-write)",
                    "- Network targets: "
                    f"{_md_code(json.dumps(report.sandbox.network_targets, ensure_ascii=False))}",
                    "- Forwarded environment names: "
                    f"{_md_code(json.dumps([name for name, _ in report.sandbox.environment], ensure_ascii=False))}",
                    "- Devices: "
                    f"{_md_code(json.dumps(report.sandbox.devices, ensure_ascii=False))}",
                    f"- Read-only container root: `{report.sandbox.read_only_root}`",
                    f"- Drop Linux capabilities: `{report.sandbox.drop_capabilities}`",
                    "- Limits: "
                    f"CPU `{report.sandbox.limits.cpus}`, memory `{report.sandbox.limits.memory_mb} MiB`, "
                    f"PIDs `{report.sandbox.limits.pids}`, timeout `{report.sandbox.limits.timeout_seconds}s`, "
                    f"output `{report.sandbox.limits.output_mb} MiB` / `{report.sandbox.limits.output_files}` files, "
                    f"/tmp `{report.sandbox.limits.temporary_mb} MiB`, /dev/shm "
                    f"`{report.sandbox.limits.shared_memory_mb} MiB`, core dumps disabled",
                ]
            )
        if report.security_assessment:
            assessment = report.security_assessment
            lines.extend(
                [
                    "",
                    "## Security preflight verdict",
                    "",
                    f"- Verdict: **{assessment.verdict.value}**",
                    f"- Risk score: `{assessment.risk_score}/100`",
                    f"- Summary: {_md_text(assessment.summary)}",
                ]
            )
            lines.extend(
                f"- Evidence: {_md_text(reason)}" for reason in assessment.reasons
            )
        if report.reflections:
            lines.extend(["", "## Replanning history", ""])
            for item in report.reflections:
                lines.append(
                    f"- {_md_code(item.classification)} — {_md_text(item.explanation)}"
                )
        lines.extend(["", "## Reproduction", ""])
        lines.append(
            "Re-run argv is recorded as JSON. A rerun creates a new sanitized snapshot; "
            "compare its reported digest with this report."
        )
        lines.extend(f"- {_md_code(item)}" for item in report.reproduction)
        lines.extend(["", "## Files created or changed", ""])
        lines.extend(
            "- " + _md_code("target-controlled artifact path omitted")
            for _item in report.files_changed
        )
        if not report.files_changed:
            lines.append("- None observed.")
        if report.notes:
            lines.extend(["", "## Notes", ""])
            lines.extend(f"- {_md_text(item)}" for item in report.notes)
        return "\n".join(lines) + "\n"

    def write(
        self,
        report: AgentReport,
        path: Path,
        *,
        forbidden_roots: tuple[Path, ...] = (),
    ) -> None:
        requested = Path(path).absolute()
        canonical_forbidden = tuple(
            Path(root).resolve(strict=False) for root in forbidden_roots
        )
        prospective = requested.resolve(strict=False)
        for root in canonical_forbidden:
            if prospective == root or prospective.is_relative_to(root):
                raise ValueError(
                    "Report path must be disjoint from repository and sandbox output."
                )
        requested.parent.mkdir(parents=True, exist_ok=True)
        parent = requested.parent.resolve(strict=True)
        target = parent / requested.name
        for root in canonical_forbidden:
            if target == root or target.is_relative_to(root):
                raise ValueError("Report path must be disjoint from repository and sandbox output.")
        try:
            if target.is_symlink():
                raise ValueError("Refusing to overwrite a symbolic-link report path.")
        except OSError as error:
            raise ValueError(f"Could not validate report path: {target}") from error

        content = self.json_text(report) if target.suffix.lower() == ".json" else self.markdown(report)
        encoded = content.encode("utf-8")
        temporary = parent / f".{target.name}.tmp-{uuid.uuid4().hex}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _one_line(value: object) -> str:
    portable = "".join(
        f"\\u{ord(character):04x}"
        if 0xD800 <= ord(character) <= 0xDFFF
        else character
        for character in str(value)
    )
    text = " ".join(portable.splitlines()).replace("\x00", "�")
    return "".join(
        character if character >= " " or character == "\t" else "�"
        for character in text
    )


def _md_text(value: object) -> str:
    text = html.escape(_one_line(value), quote=False)
    for marker in ("\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", ".", "!", "|"):
        text = text.replace(marker, f"\\{marker}")
    return text


def _md_code(value: object) -> str:
    return f"<code>{html.escape(_one_line(value), quote=False)}</code>"
