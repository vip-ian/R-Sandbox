"""Safe replanning rules for observed execution failures."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from r_sandbox.models import CapabilityCategory, ExecutionPlan, ExecutionResult, Reflection
from r_sandbox.policy.identity import capability_request_id


class ReflectionAgent:
    def reflect(self, result: ExecutionResult) -> Reflection:
        text = f"{result.stderr}\n{result.stdout}".lower()
        if result.status.value == "runtime_unavailable":
            return Reflection("runtime_unavailable", "The configured isolated runtime is unavailable.")
        if "permission denied" in text or "read-only file system" in text:
            return Reflection(
                "permission",
                "Execution requested an authority not present in the contract; it was not widened automatically.",
            )
        if "no module named" in text or "modulenotfounderror" in text:
            return Reflection(
                "dependency",
                "A dependency is missing. Installation needs a new reviewed plan and possibly network approval.",
                plan_changes=("Resolve dependencies in an immutable image rather than modifying the repository.",),
            )
        if "command not found" in text and "python" in text:
            return Reflection(
                "command",
                "The image does not expose the selected Python executable.",
                should_retry=True,
                plan_changes=("Switch the interpreter token between python and python3.",),
            )
        if "out of memory" in text or result.exit_code in {137, 143}:
            return Reflection(
                "resource",
                "The process exceeded a resource or time boundary; limits were not raised automatically.",
            )
        if result.exit_code == 0:
            return Reflection("success", "The bounded execution completed successfully.")
        return Reflection("execution", "The command failed without a recognized safe automatic recovery.")

    def replan(
        self,
        plan: ExecutionPlan,
        reflection: Reflection,
        repository: Path,
        repository_digest: str = "",
        authorization_context: str = "",
    ) -> ExecutionPlan:
        if (
            not reflection.should_retry
            or reflection.classification not in {"command", "command_or_config"}
            or not plan.steps
        ):
            return plan
        step = plan.steps[0]
        executable = "python3" if step.argv[0] == "python" else "python"
        capabilities = []
        for request in step.capabilities:
            if (
                request.category == CapabilityCategory.PROCESS
                and request.action == "execute"
                and request.target == step.argv[0]
            ):
                justification = (
                    "Use the alternate Python executable after a "
                    "command-resolution failure."
                )
                request = replace(
                    request,
                    request_id=capability_request_id(
                        repository,
                        plan.goal,
                        request.category,
                        request.action,
                        executable,
                        request.risk,
                        request.confidence,
                        repository_digest,
                        justification,
                        request.evidence,
                        authorization_context,
                    ),
                    target=executable,
                    justification=justification,
                )
            capabilities.append(request)
        changed = replace(
            step,
            step_id=f"execute-entrypoint-{plan.attempt + 1}",
            argv=(executable, *step.argv[1:]),
            capabilities=tuple(capabilities),
        )
        return replace(plan, steps=(changed,), attempt=plan.attempt + 1)
