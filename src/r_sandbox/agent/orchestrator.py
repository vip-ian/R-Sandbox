"""Central R-Sandbox research-security agent loop."""

from __future__ import annotations

from dataclasses import replace
from enum import StrEnum
import json
from pathlib import Path
from uuid import uuid4

from r_sandbox.agent.planner import ResearchPlanner
from r_sandbox.agent.environment_planner import EnvironmentPlanner
from r_sandbox.agent.reflection import ReflectionAgent
from r_sandbox.agent.repository_understanding import RepositoryUnderstanding
from r_sandbox.agent.risk_reasoner import RiskReasoner
from r_sandbox.agent.security_assessor import SecurityAssessor
from r_sandbox.models import (
    AgentOutcome,
    AgentPhase,
    AgentReport,
    ExecutionResult,
    PhaseRecord,
    RuntimeEvent,
    RuntimeEvidenceSource,
    canonical_execution_result,
)
from r_sandbox.policy import (
    PolicyConfig,
    PolicyEngine,
    capability_authorization_context,
)
from r_sandbox.tools.execution_supervisor import (
    DockerExecutionSupervisor,
    DryRunExecutionSupervisor,
    ExecutionSupervisor,
)
from r_sandbox.tools.runtime_observer import (
    ManifestLimitExceeded,
    RuntimeObserver,
    capture_output_manifest,
    diff_output_manifests,
)
from r_sandbox.tools.repository_snapshot import RepositorySnapshotter
from r_sandbox.tools.sandbox_builder import SandboxBuilder


class AgentMode(StrEnum):
    """No untrusted code is executed unless SHADOW is selected explicitly."""

    ANALYZE = "analyze"
    DRY_RUN = "dry-run"
    SHADOW = "shadow"


class RSandboxAgent:
    """Coordinate understanding, least-authority construction, and preflight."""

    def __init__(
        self,
        *,
        understanding: RepositoryUnderstanding | None = None,
        reasoner: RiskReasoner | None = None,
        planner: ResearchPlanner | None = None,
        policy: PolicyEngine | None = None,
        builder: SandboxBuilder | None = None,
        observer: RuntimeObserver | None = None,
        reflector: ReflectionAgent | None = None,
        assessor: SecurityAssessor | None = None,
        environment_planner: EnvironmentPlanner | None = None,
        snapshotter: RepositorySnapshotter | None = None,
        execution_supervisor: ExecutionSupervisor | None = None,
        dry_run_supervisor: ExecutionSupervisor | None = None,
    ) -> None:
        self.understanding = understanding or RepositoryUnderstanding()
        self.reasoner = reasoner or RiskReasoner()
        self.planner = planner or ResearchPlanner()
        self.policy = policy or PolicyEngine()
        self.builder = builder or SandboxBuilder()
        self.observer = observer or RuntimeObserver()
        self.reflector = reflector or ReflectionAgent()
        self.assessor = assessor or SecurityAssessor()
        self.environment_planner = environment_planner or EnvironmentPlanner()
        self.snapshotter = snapshotter or RepositorySnapshotter()
        self.execution_supervisor = execution_supervisor or DockerExecutionSupervisor()
        self.dry_run_supervisor = dry_run_supervisor or DryRunExecutionSupervisor()

    def run(
        self,
        repository: Path,
        goal: str,
        *,
        output: Path,
        mode: AgentMode = AgentMode.ANALYZE,
        image: str = "python:3.11-slim",
        approved_request_ids: frozenset[str] = frozenset(),
        network_allowlist: frozenset[str] = frozenset(),
        max_attempts: int = 2,
    ) -> AgentReport:
        try:
            mode = AgentMode(mode)
        except (TypeError, ValueError) as error:
            raise ValueError(f"Unsupported agent mode: {mode!r}") from error
        goal = _require_api_text(goal, "goal", maximum=16_384)
        repository = repository.resolve(strict=True)
        if not repository.is_dir():
            raise ValueError("Repository input must be a directory.")
        if not goal.strip():
            raise ValueError("A non-empty research goal is required.")
        output = output.resolve(strict=False)
        if (
            output == repository
            or output.is_relative_to(repository)
            or repository.is_relative_to(output)
        ):
            raise ValueError("Output and repository directories must be disjoint.")
        authorization_context = capability_authorization_context(image)

        with self.snapshotter.create(repository) as snapshot:
            return self._run_snapshot(
                repository,
                goal.strip(),
                execution_repository=snapshot.root,
                snapshot_digest=snapshot.digest,
                snapshot_warnings=snapshot.warnings,
                snapshot_omissions=snapshot.omitted_paths,
                output=output,
                mode=mode,
                image=image,
                approved_request_ids=approved_request_ids,
                network_allowlist=network_allowlist,
                max_attempts=max_attempts,
                authorization_context=authorization_context,
            )

    def _run_snapshot(
        self,
        repository: Path,
        goal: str,
        *,
        execution_repository: Path,
        snapshot_digest: str,
        snapshot_warnings: tuple[str, ...],
        snapshot_omissions: tuple[str, ...],
        output: Path,
        mode: AgentMode,
        image: str,
        approved_request_ids: frozenset[str],
        network_allowlist: frozenset[str],
        max_attempts: int,
        authorization_context: str,
    ) -> AgentReport:
        report = AgentReport(AgentOutcome.ANALYZED, goal.strip(), str(repository))

        self._record(
            report,
            AgentPhase.OBSERVE,
            "Created a bounded, sanitized repository snapshot; the source checkout will never be mounted.",
        )
        analyzed_profile = self.understanding.analyze(execution_repository, goal.strip())
        profile = replace(
            analyzed_profile,
            root=str(repository),
            warnings=tuple(dict.fromkeys((*snapshot_warnings, *analyzed_profile.warnings))),
            snapshot_digest=snapshot_digest,
            snapshot_omissions=snapshot_omissions,
            authorization_context=authorization_context,
        )
        report.profile = profile
        environment_plan = self.environment_planner.plan(profile, image)
        report.environment_plan = environment_plan
        assessment_warnings = tuple(
            dict.fromkeys((*profile.warnings, *environment_plan.warnings))
        )
        self._record(
            report,
            AgentPhase.UNDERSTAND,
            f"Identified {len(profile.entrypoints)} entrypoint(s), {len(profile.dependencies)} dependencies, "
            f"and {len(profile.findings)} security-relevant behavior(s).",
        )

        entrypoint = self.planner.select_entrypoint(profile)
        capabilities = self.reasoner.infer(profile, entrypoint)
        plan = self.planner.plan(profile, capabilities, entrypoint=entrypoint)
        report.plan = plan
        self._record(report, AgentPhase.PLAN, plan.summary)

        config = PolicyConfig(
            repository=repository,
            output=output,
            approved_request_ids=approved_request_ids,
            network_allowlist=network_allowlist,
            repository_digest=snapshot_digest,
            authorization_context=authorization_context,
            approval_context_immutable=environment_plan.image_pinned,
        )
        authorization = self.policy.authorize(plan, config)
        report.authorization = authorization
        if self._malformed_proposal_rejected(authorization):
            report.plan = self._quarantined_plan(plan, authorization)
            report.outcome = AgentOutcome.BLOCKED
            report.security_assessment = self.assessor.assess(
                profile.findings,
                authorization,
                None,
                assessment_warnings,
            )
            report.notes.append(
                "A malformed semantic-layer proposal was quarantined at the "
                "deterministic policy boundary; no sandbox was built or executed."
            )
            self._record(
                report,
                AgentPhase.REPORT,
                "Malformed capability proposal blocked before host effects.",
            )
            return report
        report.reproduction.append(
            self._reproduction_argv(
                mode=mode,
                repository=repository,
                goal=goal,
                output=output,
                image=image,
                approved_request_ids=approved_request_ids,
                network_allowlist=network_allowlist,
            )
        )
        self._record(
            report,
            AgentPhase.AUTHORIZE,
            f"Policy allowed {len(authorization.allowed)}, denied {len(authorization.denied)}, "
            f"and held {len(authorization.pending)} request(s) for approval.",
        )

        # Denied observed behavior narrows the sandbox; it does not prevent a
        # security preflight.  This is what lets the shadow run turn attempted
        # secret access or egress into evidence without granting that authority.
        report.security_assessment = self.assessor.assess(
            profile.findings, authorization, None, assessment_warnings
        )
        if not plan.steps:
            report.notes.append("No safe entrypoint was inferred, so dynamic preflight was not attempted.")
            self._record(report, AgentPhase.REPORT, "Static-only security assessment completed.")
            return report
        if mode == AgentMode.ANALYZE:
            report.notes.append("Analysis mode never executes repository code.")
            self._record(report, AgentPhase.REPORT, "Static preflight completed; shadow execution remains pending.")
            return report

        # The user-facing output root may contain prior artifacts or secrets.
        # Never mount it. Each plan gets an unpredictable, atomically-created
        # empty child that is the only host directory exposed as /output.
        run_output = output / f"run-{uuid4().hex}"

        before_manifest = None
        if mode == AgentMode.SHADOW:
            try:
                before_manifest = capture_output_manifest(run_output)
            except (ManifestLimitExceeded, OSError, ValueError) as error:
                result = self._manifest_failure_result(
                    run_output, error, before_execution=True
                )
                report.execution = result
                report.execution_history.append(result)
                report.outcome = result.status
                reflection = self.observer.inspect(result)
                report.reflections.append(reflection)
                report.security_assessment = self.assessor.assess(
                    profile.findings, authorization, result, assessment_warnings
                )
                report.notes.append(
                    "Shadow execution was not started because the initial output directory "
                    "could not be inventoried within safety limits."
                )
                self._record(report, AgentPhase.REPORT, reflection.explanation)
                return report
        current_plan = plan
        attempts = max(1, min(max_attempts, 3))
        for attempt_index in range(attempts):
            step = current_plan.steps[0]
            sandbox = self.builder.build(
                execution_repository,
                run_output,
                step,
                authorization,
                image=image,
                require_fresh_output=attempt_index == 0,
            )
            sandbox = replace(
                sandbox,
                source_repository=str(repository),
                snapshot_digest=snapshot_digest,
            )
            report.sandbox = sandbox
            if attempt_index == 0:
                report.notes.append(
                    "Only the fresh per-run artifact directory was mounted at /output; "
                    f"preexisting content under {output} was not exposed."
                )
            self._record(
                report,
                AgentPhase.BUILD,
                "Built a project-specific sandbox contract: repository read-only, output writable, "
                "host secrets absent, and network disabled unless enforced by a narrow adapter.",
            )

            if mode == AgentMode.DRY_RUN:
                result = canonical_execution_result(
                    self.dry_run_supervisor.execute(sandbox)
                )
                report.execution = result
                report.execution_history.append(result)
                report.outcome = result.status
                report.security_assessment = self.assessor.assess(
                    profile.findings,
                    authorization,
                    result,
                    assessment_warnings,
                )
                reflection = self.observer.inspect(result)
                report.reflections.append(reflection)
                if result.status == AgentOutcome.PLANNED:
                    report.notes.append(
                        "Dry-run mode generated an audit command but did not execute it. "
                        "Its sanitized snapshot path is temporary; use the reproduction argv "
                        "to create and verify a fresh snapshot before a real run."
                    )
                    message = "Sandbox plan generated without running code."
                else:
                    report.notes.append(
                        "Dry-run validation rejected a sandbox property; no code was executed."
                    )
                    message = "Sandbox plan failed runtime-enforceability validation."
                self._record(report, AgentPhase.REPORT, message)
                return report

            self._record(report, AgentPhase.EXECUTE, "Started an explicit sandboxed shadow execution.")
            result = canonical_execution_result(
                self.execution_supervisor.execute(sandbox)
            )
            report.execution = result
            report.execution_history.append(result)
            self._record(
                report,
                AgentPhase.MONITOR,
                f"Observed {len(result.events)} runtime event(s); exit code was {result.exit_code!r}.",
            )
            reflection = self.observer.inspect(result)
            report.reflections.append(reflection)
            self._record(report, AgentPhase.REFLECT, reflection.explanation)
            report.security_assessment = self.assessor.assess(
                profile.findings, authorization, result, assessment_warnings
            )
            report.outcome = result.status

            if not reflection.should_retry or attempt_index + 1 >= attempts:
                break
            candidate = self.reflector.replan(
                current_plan,
                reflection,
                repository,
                snapshot_digest,
                authorization_context,
            )
            if candidate == current_plan:
                report.notes.append(
                    "Reflection found no deterministic, authority-preserving plan change; no identical retry was run."
                )
                break
            candidate_authorization = self.policy.authorize(candidate, config)
            self._record(report, AgentPhase.REPLAN, "; ".join(reflection.plan_changes))
            if candidate_authorization.pending or self._required_authority_denied(candidate_authorization):
                report.notes.append("A retry was proposed but stopped at the authorization boundary.")
                break
            current_plan = candidate
            authorization = candidate_authorization
            report.plan = candidate
            report.authorization = candidate_authorization

        try:
            after_manifest = capture_output_manifest(run_output)
            assert before_manifest is not None
            report.files_changed = list(
                diff_output_manifests(before_manifest, after_manifest).changed
            )
        except (ManifestLimitExceeded, OSError, ValueError) as error:
            manifest_event = self._manifest_failure_result(
                run_output, error, before_execution=False
            ).events[0]
            assert report.execution is not None
            report.execution = replace(
                report.execution,
                status=AgentOutcome.FAILED,
                exit_code=None,
                events=(*report.execution.events, manifest_event),
            )
            if report.execution_history:
                report.execution_history[-1] = report.execution
            report.outcome = AgentOutcome.FAILED
            reflection = self.observer.inspect(report.execution)
            report.reflections.append(reflection)
            report.security_assessment = self.assessor.assess(
                profile.findings,
                authorization,
                report.execution,
                assessment_warnings,
            )
            report.notes.append(
                "Output changes could not be completely inventoried; the verdict was "
                "downgraded rather than dropping the report."
            )
            self._record(report, AgentPhase.REFLECT, reflection.explanation)
        self._record(report, AgentPhase.REPORT, "Combined static and shadow-execution evidence into a verdict.")
        return report

    @staticmethod
    def _reproduction_argv(
        *,
        mode: AgentMode,
        repository: Path,
        goal: str,
        output: Path,
        image: str,
        approved_request_ids: frozenset[str],
        network_allowlist: frozenset[str],
    ) -> str:
        argv = [
            "r-sandbox",
            mode.value,
            str(repository),
            "--goal",
            goal,
            "--output",
            str(output),
            "--image",
            image,
        ]
        for request_id in sorted(approved_request_ids):
            argv.extend(("--approve", request_id))
        for hostname in sorted(network_allowlist):
            argv.extend(("--allow-domain", hostname))
        return json.dumps(argv, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _required_authority_denied(authorization) -> bool:
        required_targets = {
            "<repository>",
            "<output>",
            "<temporary>",
            "<shared-memory>",
            "python",
            "python3",
            "1",
            "16",
            "64",
            "1024",
        }
        return any(item.request.target in required_targets for item in authorization.denied)

    @staticmethod
    def _malformed_proposal_rejected(authorization) -> bool:
        return any(
            item.request.action == "invalid_proposal"
            or item.reason.startswith("Authorization aborted because the plan contains")
            for item in authorization.decisions
        )

    @staticmethod
    def _quarantined_plan(plan, authorization):
        decisions = iter(authorization.decisions)
        steps = []
        for step in plan.steps:
            capabilities = tuple(next(decisions).request for _ in step.capabilities)
            steps.append(replace(step, capabilities=capabilities))
        return replace(plan, steps=tuple(steps))

    @staticmethod
    def _manifest_failure_result(
        output: Path,
        error: Exception,
        *,
        before_execution: bool,
    ) -> ExecutionResult:
        if isinstance(error, ManifestLimitExceeded):
            detail = (
                "Output manifest exceeded a configured traversal bound: "
                f"{error.limit_name}={error.limit}, observed at least {error.observed}."
            )
        else:
            detail = (
                "Output manifest was unsafe or unavailable: "
                f"{type(error).__name__}; target-derived path text was omitted."
            )
        return ExecutionResult(
            status=AgentOutcome.BLOCKED if before_execution else AgentOutcome.FAILED,
            exit_code=None,
            stderr=detail,
            events=(
                RuntimeEvent(
                    event_type="observer",
                    action="output_manifest",
                    target="fresh-output",
                    allowed=False,
                    detail=detail,
                    source=RuntimeEvidenceSource.SUPERVISOR,
                ),
            ),
        )

    @staticmethod
    def _record(report: AgentReport, phase: AgentPhase, message: str) -> None:
        report.timeline.append(PhaseRecord(phase, message))


def _require_api_text(value: object, field: str, *, maximum: int) -> str:
    """Validate user-authored scalar text before repository analysis begins."""

    if type(value) is not str or not value or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{field} must be non-empty bounded text")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field} must be valid UTF-8 text without lone surrogates") from error
    return value
