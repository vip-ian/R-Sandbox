"""Turn raw execution results into conservative replanning signals."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ...models import (
    AgentOutcome,
    ExecutionResult,
    Reflection,
    canonical_execution_result,
)


DEPENDENCY_OR_VERSION = "dependency_or_version"
PERMISSION = "permission"
COMMAND_OR_CONFIG = "command_or_config"
RESOURCE = "resource"
RUNTIME_UNAVAILABLE = "runtime_unavailable"
SUCCESS = "success"
DRY_RUN = "dry_run"
UNKNOWN_FAILURE = "unknown_failure"
BLOCKED_BEHAVIOR = "blocked_behavior"
INCOMPLETE_OBSERVATION = "incomplete_observation"


_PATTERNS = {
    RUNTIME_UNAVAILABLE: re.compile(
        r"cannot connect to (?:the )?docker|docker daemon is not running|"
        r"is the docker daemon running|docker runtime could not be started|"
        r"docker executable is unavailable|failed to connect to the docker api",
        re.IGNORECASE,
    ),
    RESOURCE: re.compile(
        r"timed?\s*out|timeout|out of memory|oom(?:killed)?|memory limit|"
        r"no space left on device|resource temporarily unavailable|"
        r"too many open files|pids? limit|killed",
        re.IGNORECASE,
    ),
    PERMISSION: re.compile(
        r"permission denied|operation not permitted|read-only file system|"
        r"access (?:is )?denied|not authorized|forbidden|network is unreachable|"
        r"egress .{0,30}(?:blocked|denied)|requires? approval",
        re.IGNORECASE,
    ),
    DEPENDENCY_OR_VERSION: re.compile(
        r"modulenotfounderror|no module named|importerror|distributionnotfound|"
        r"versionconflict|requires python|unsupported python version|"
        r"could not find a version that satisfies|no matching distribution|"
        r"no such image|package .{0,60} not found|undefined symbol|"
        r"shared librar(?:y|ies).{0,30}(?:not found|cannot open)",
        re.IGNORECASE,
    ),
    COMMAND_OR_CONFIG: re.compile(
        r"executable file not found|command not found|unknown (?:option|argument)|"
        r"unrecognized arguments?|invalid (?:option|argument|configuration)|"
        r"usage:|no such file or directory|can't open file|cannot open file|"
        r"syntaxerror|configuration error|config(?:uration)? file .{0,30}not found",
        re.IGNORECASE,
    ),
}


@dataclass(slots=True)
class RuntimeObserver:
    """Classify failures without executing or modifying target code."""

    explanation_limit: int = 500

    def inspect(self, result: ExecutionResult) -> Reflection:
        result = canonical_execution_result(result)
        classification = self._classification(result)
        detail = self._detail(result)
        context = self._security_context(result)

        if classification == SUCCESS:
            return Reflection(
                classification=SUCCESS,
                explanation=f"Sandbox execution completed successfully. {context}".strip(),
            )
        if classification == DRY_RUN:
            return Reflection(
                classification=DRY_RUN,
                explanation="Execution was previewed; no repository code was run.",
            )
        if classification == BLOCKED_BEHAVIOR:
            return Reflection(
                classification=classification,
                explanation=(
                    "Shadow execution reached behavior blocked by the sandbox. "
                    f"{context} {detail}"
                ).strip(),
                should_retry=False,
                plan_changes=(
                    "Treat the blocked attempts as security evidence; do not grant the capability automatically.",
                ),
            )
        if classification == INCOMPLETE_OBSERVATION:
            return Reflection(
                classification=classification,
                explanation=(
                    "Shadow execution finished without trustworthy dynamic telemetry. "
                    f"{context} {detail}"
                ).strip(),
                should_retry=False,
                plan_changes=(
                    "Restore mandatory runtime instrumentation before making a safety assessment.",
                ),
            )
        if classification == RUNTIME_UNAVAILABLE:
            return Reflection(
                classification=classification,
                explanation=f"The isolated runtime is unavailable. {context} {detail}".strip(),
                should_retry=False,
                plan_changes=(
                    "Install or start the approved container runtime, then create a new run.",
                ),
            )
        if classification == PERMISSION:
            return Reflection(
                classification=classification,
                explanation=f"The sandbox or policy denied a required operation. {context} {detail}".strip(),
                should_retry=False,
                plan_changes=(
                    "Identify the exact missing capability and send it through policy review; do not broaden access automatically.",
                ),
            )
        if classification == DEPENDENCY_OR_VERSION:
            return Reflection(
                classification=classification,
                explanation=f"A dependency or runtime version is incompatible or missing. {context} {detail}".strip(),
                should_retry=True,
                plan_changes=(
                    "Pin or provide the dependency in a reviewed sandbox image before retrying.",
                ),
            )
        if classification == COMMAND_OR_CONFIG:
            return Reflection(
                classification=classification,
                explanation=f"The entrypoint, arguments, path, or configuration appear invalid. {context} {detail}".strip(),
                should_retry=True,
                plan_changes=(
                    "Re-check repository documentation and revise argv or configuration without expanding permissions.",
                ),
            )
        if classification == RESOURCE:
            return Reflection(
                classification=classification,
                explanation=f"Execution reached a resource boundary. {context} {detail}".strip(),
                should_retry=True,
                plan_changes=(
                    "Reduce the workload first; request a narrowly scoped limit change only when evidence justifies it.",
                ),
            )
        return Reflection(
            classification=UNKNOWN_FAILURE,
            explanation=f"Execution failed for an unclassified reason. {context} {detail}".strip(),
            should_retry=False,
            plan_changes=("Collect additional sandbox-only diagnostics before retrying.",),
        )

    @staticmethod
    def _classification(result: ExecutionResult) -> str:
        if result.status == AgentOutcome.RUNTIME_UNAVAILABLE:
            return RUNTIME_UNAVAILABLE
        blocked_evidence = [
            event
            for event in result.events
            if not event.allowed
            and event.event_type.lower()
            in {
                "filesystem",
                "network",
                "process",
                "secret",
                "device",
                "resource",
                "side_effect",
            }
        ]
        if blocked_evidence:
            return BLOCKED_BEHAVIOR
        if result.status == AgentOutcome.PLANNED and any(
            event.event_type == "dry_run" for event in result.events
        ):
            return DRY_RUN
        if any(event.event_type.lower() == "observer" for event in result.events):
            return INCOMPLETE_OBSERVATION
        if result.status == AgentOutcome.SUCCEEDED and result.exit_code == 0:
            return SUCCESS

        event_types = {event.event_type.lower() for event in result.events}
        if any(
            not event.allowed
            and event.event_type.lower() == "runtime"
            and event.action.lower() == "invoke"
            for event in result.events
        ):
            return RUNTIME_UNAVAILABLE
        if any(
            event.event_type.lower() == "resource"
            and event.source.value in {"supervisor", "independent_observer"}
            for event in result.events
        ):
            return RESOURCE
        if any(not event.allowed for event in result.events) and event_types.intersection(
            {"network", "filesystem", "permission", "policy", "authorization"}
        ):
            return PERMISSION

        target_started = any(
            event.source.value == "target_telemetry"
            and event.event_type == "runtime"
            and event.action == "audit_hook"
            for event in result.events
        )
        # Once target code has started, target-selected exit codes and output
        # strings cannot trigger automatic authority or interpreter changes.
        if target_started:
            return UNKNOWN_FAILURE
        if result.exit_code == 126:
            return PERMISSION
        if result.exit_code == 127:
            return COMMAND_OR_CONFIG
        if "resource" in event_types or result.exit_code in {137, 143}:
            return RESOURCE

        diagnostic = "\n".join((result.stderr, result.stdout))
        for classification in (
            RESOURCE,
            PERMISSION,
            DEPENDENCY_OR_VERSION,
            COMMAND_OR_CONFIG,
        ):
            if _PATTERNS[classification].search(diagnostic):
                return classification
        return UNKNOWN_FAILURE

    @staticmethod
    def _security_context(result: ExecutionResult) -> str:
        blocked = [event for event in result.events if not event.allowed]
        exit_summary = (
            "exit_code=not_started"
            if result.exit_code is None
            else f"exit_code={result.exit_code}"
        )
        if not blocked:
            return f"{exit_summary}; blocked_attempts=0."
        rendered = []
        for event in blocked[:5]:
            if event.source.value == "target_telemetry":
                rendered.append(
                    "target_telemetry:reported_event:"
                    "<target-controlled-content-omitted>"
                )
            else:
                target = event.target.replace("\r", " ").replace("\n", " ")[:160]
                rendered.append(f"{event.event_type}:{event.action}:{target}")
        suffix = f", +{len(blocked) - 5} more" if len(blocked) > 5 else ""
        return (
            f"{exit_summary}; blocked_attempts={len(blocked)} "
            f"[{'; '.join(rendered)}{suffix}]."
        )

    def _detail(self, result: ExecutionResult) -> str:
        if result.stderr:
            return (
                f"Target stderr was captured internally and omitted from the report "
                f"(characters={len(result.stderr)})."
            )
        supervisor_details = [
            event.detail.strip()
            for event in result.events
            if event.source.value == "supervisor" and event.detail.strip()
        ]
        if supervisor_details:
            detail = supervisor_details[-1]
            if len(detail) > self.explanation_limit:
                detail = detail[: max(0, self.explanation_limit - 3)] + "..."
            return detail
        if result.exit_code is not None:
            return f"Process exited with code {result.exit_code}."
        return ""
