"""Generate a constrained execution plan from repository understanding."""

from __future__ import annotations

from pathlib import PurePosixPath

from r_sandbox.models import CapabilityRequest, ExecutionPlan, PlanStep, RepositoryProfile


_EXECUTABLES = {"python", "python3"}
_CONTROL_TOKENS = {";", "&&", "||", "|", ">", ">>", "<", "`"}


class ResearchPlanner:
    def plan(
        self,
        profile: RepositoryProfile,
        capabilities: tuple[CapabilityRequest, ...],
        attempt: int = 1,
        *,
        entrypoint=None,
    ) -> ExecutionPlan:
        if not profile.entrypoints:
            return ExecutionPlan(
                goal=profile.goal,
                summary="Repository understood, but no safe executable entrypoint was inferred.",
                steps=(),
                assumptions=("README commands are treated as evidence and are never executed directly.",),
                attempt=attempt,
            )
        entrypoint = entrypoint or self.select_entrypoint(profile)
        argv = self._validate_argv(entrypoint.argv)
        step = PlanStep(
            step_id=f"execute-entrypoint-{attempt}",
            purpose=f"Run {entrypoint.path} to pursue: {profile.goal}",
            argv=argv,
            capabilities=capabilities,
        )
        return ExecutionPlan(
            goal=profile.goal,
            summary="Execute one statically identified entrypoint in a least-authority sandbox.",
            steps=(step,),
            assumptions=(
                "The repository is untrusted and mounted read-only.",
            "Only the fresh /output host bind is persistently writable; bounded /tmp and /dev/shm are ephemeral.",
                "Network and host secrets remain unavailable unless separately authorized.",
            ),
            attempt=attempt,
        )

    @staticmethod
    def select_entrypoint(profile: RepositoryProfile):
        if not profile.entrypoints:
            return None
        goal = profile.goal.lower()
        intent_markers = {
            "train": {"train", "fit", "학습"},
            "evaluate": {"evaluate", "evaluation", "benchmark", "평가", "재현"},
            "eval": {"evaluate", "evaluation", "benchmark", "평가"},
            "predict": {"predict", "prediction", "예측"},
            "infer": {"infer", "inference", "추론"},
            "preprocess": {"preprocess", "prepare", "전처리"},
            "test": {"test", "verify", "검증"},
        }

        def score(candidate):
            stem = PurePosixPath(candidate.path).stem.lower()
            markers = intent_markers.get(stem, set())
            goal_bonus = 0.3 if any(marker in goal for marker in markers) else 0.0
            return (candidate.confidence + goal_bonus, candidate.confidence, candidate.path)

        return max(profile.entrypoints, key=score)

    @staticmethod
    def _validate_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
        if not argv:
            raise ValueError("An execution plan requires a non-empty argv.")
        executable = PurePosixPath(argv[0].replace("\\", "/")).name.lower()
        if executable not in _EXECUTABLES:
            raise ValueError(f"Unsupported entrypoint executable: {executable}")
        for argument in argv:
            if not argument or "\n" in argument or "\r" in argument:
                raise ValueError("Empty or multiline command arguments are forbidden.")
            if argument in _CONTROL_TOKENS or "$(" in argument:
                raise ValueError("Shell control syntax is forbidden; plans are argv-only.")
            if argument in {"-S", "-I", "-E"}:
                raise ValueError("Python flags that bypass the shadow audit layer are forbidden.")
            normalized = PurePosixPath(argument.replace("\\", "/"))
            if ".." in normalized.parts:
                raise ValueError("Parent traversal is forbidden in command arguments.")
        return argv
