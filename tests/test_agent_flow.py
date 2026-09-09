from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from r_sandbox.agent.orchestrator import AgentMode, RSandboxAgent
from r_sandbox.agent.planner import ResearchPlanner
from r_sandbox.agent.reporter import ReportGenerator
from r_sandbox.agent.risk_reasoner import RiskReasoner
from r_sandbox.agent.security_assessor import SecurityAssessor
from r_sandbox.cli import _exit_code
from r_sandbox.models import (
    AgentOutcome,
    AgentReport,
    Authorization,
    CapabilityCategory,
    CapabilityRequest,
    Decision,
    Evidence,
    ExecutionResult,
    Finding,
    PolicyDecision,
    RiskLevel,
    RuntimeEvidenceSource,
    RuntimeEvent,
    SecurityVerdict,
    canonical_agent_report,
    canonical_execution_result,
)
from r_sandbox.tools.runtime_observer import (
    ManifestLimitExceeded,
    OutputManifest,
    RuntimeObserver,
)


ROOT = Path(__file__).resolve().parents[1]
SAFE = ROOT / "examples" / "safe_research_repo"
RISKY = ROOT / "examples" / "risky_research_repo"


class ScriptedSupervisor:
    def __init__(self, result: ExecutionResult) -> None:
        self.result = result
        self.calls = 0

    def execute(self, _spec):
        self.calls += 1
        return self.result


class SequenceSupervisor:
    def __init__(self, results: list[ExecutionResult]) -> None:
        self.results = iter(results)
        self.specs = []

    def execute(self, spec):
        self.specs.append(spec)
        return next(self.results)


class ArtifactWritingSupervisor:
    def __init__(self) -> None:
        self.specs = []

    def execute(self, spec):
        self.specs.append(spec)
        output = Path(spec.output)
        (output / "result.txt").write_text("new result\n", encoding="utf-8")
        return ExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
            events=(RuntimeEvent("runtime", "audit_hook", "python", True),),
        )


class NonFiniteReasoner:
    def infer(self, profile, entrypoint):
        capabilities = list(RiskReasoner().infer(profile, entrypoint))
        capabilities[0] = replace(capabilities[0], confidence=float("nan"))
        return tuple(capabilities)


class TwoStepPlanner(ResearchPlanner):
    def plan(self, profile, capabilities, attempt=1, *, entrypoint=None):
        base = super().plan(
            profile,
            capabilities,
            attempt=attempt,
            entrypoint=entrypoint,
        )
        assert base.steps
        second = replace(
            base.steps[0],
            step_id="unexecuted-second-step",
            argv=("python", "never-run.py"),
        )
        return replace(base, steps=(base.steps[0], second))


class AgentFlowTests(unittest.TestCase):
    def test_report_rejects_outcome_that_contradicts_final_execution(self) -> None:
        failed = ExecutionResult(status=AgentOutcome.FAILED, exit_code=1)
        assessment = SecurityAssessor().assess((), Authorization(()), failed)
        report = AgentReport(
            outcome=AgentOutcome.SUCCEEDED,
            goal="test",
            repository=str(SAFE),
            execution=failed,
            execution_history=[failed],
            security_assessment=assessment,
        )

        with self.assertRaisesRegex(ValueError, "outcome must match"):
            canonical_agent_report(report)
        with self.assertRaisesRegex(ValueError, "outcome must match"):
            ReportGenerator().json_text(report)

    def test_report_requires_execution_and_history_to_name_the_same_final_result(self) -> None:
        failed = ExecutionResult(status=AgentOutcome.FAILED, exit_code=1)
        other_failure = ExecutionResult(status=AgentOutcome.FAILED, exit_code=2)
        cases = (
            (
                AgentReport(
                    AgentOutcome.FAILED,
                    "test",
                    str(SAFE),
                    execution=failed,
                ),
                "non-empty execution_history",
            ),
            (
                AgentReport(
                    AgentOutcome.ANALYZED,
                    "test",
                    str(SAFE),
                    execution_history=[failed],
                ),
                "history must be empty",
            ),
            (
                AgentReport(
                    AgentOutcome.FAILED,
                    "test",
                    str(SAFE),
                    execution=failed,
                    execution_history=[other_failure],
                ),
                "equal the final",
            ),
        )

        for report, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                ValueError, message
            ):
                canonical_agent_report(report)

    def test_terminal_process_outcomes_require_execution_evidence(self) -> None:
        for outcome in (
            AgentOutcome.SUCCEEDED,
            AgentOutcome.FAILED,
            AgentOutcome.RUNTIME_UNAVAILABLE,
        ):
            with self.subTest(outcome=outcome), self.assertRaisesRegex(
                ValueError, "terminal process outcomes"
            ):
                canonical_agent_report(
                    AgentReport(outcome, "test", str(SAFE))
                )

    def test_non_execution_report_states_remain_valid(self) -> None:
        for outcome in (
            AgentOutcome.ANALYZED,
            AgentOutcome.PLANNED,
            AgentOutcome.BLOCKED,
            AgentOutcome.AWAITING_APPROVAL,
        ):
            with self.subTest(outcome=outcome):
                snapshot = canonical_agent_report(
                    AgentReport(outcome, "test", str(SAFE))
                )
                self.assertEqual(snapshot.outcome, outcome)
                self.assertIsNone(snapshot.execution)
                self.assertEqual(snapshot.execution_history, [])

    def test_mutated_assessment_cannot_fabricate_a_safe_report(self) -> None:
        assessment = SecurityAssessor().assess((), Authorization(()), None)
        object.__setattr__(assessment, "verdict", SecurityVerdict.SAFE)
        report = AgentReport(
            outcome=AgentOutcome.FAILED,
            goal="test",
            repository=str(SAFE),
            execution=ExecutionResult(status=AgentOutcome.FAILED, exit_code=1),
            security_assessment=assessment,
        )
        with self.assertRaisesRegex(ValueError, "coverage attestation"):
            ReportGenerator().json_text(report)
        with self.assertRaisesRegex(ValueError, "coverage attestation"):
            ReportGenerator().markdown(report)

        object.__setattr__(assessment, "verdict", "safe")
        with self.assertRaisesRegex(TypeError, "verdict"):
            report.to_dict()

    def test_mutated_finding_risk_is_rejected_before_scoring(self) -> None:
        finding = Finding(
            "finding-test",
            CapabilityCategory.FILESYSTEM,
            "read",
            "<repository>",
            RiskLevel.LOW,
            "test finding",
            (Evidence("train.py", "test finding", 1),),
        )
        object.__setattr__(finding, "risk", None)
        with self.assertRaisesRegex(TypeError, "risk"):
            SecurityAssessor().assess((finding,), Authorization(()), None)

    def test_dry_run_marker_cannot_hide_a_blocked_behavior_event(self) -> None:
        reflection = RuntimeObserver().inspect(
            ExecutionResult(
                status=AgentOutcome.PLANNED,
                exit_code=None,
                events=(
                    RuntimeEvent("dry_run", "preview", "docker", True),
                    RuntimeEvent(
                        "network",
                        "send",
                        "collector.invalid:443",
                        False,
                        "trusted supervisor blocked behavior",
                        RuntimeEvidenceSource.SUPERVISOR,
                    ),
                ),
            )
        )
        self.assertEqual(reflection.classification, "blocked_behavior")

    def test_execution_result_subclasses_are_rejected_at_security_boundaries(self) -> None:
        class ForgedExecutionResult(ExecutionResult):
            pass

        forged = ForgedExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
        )
        with self.assertRaisesRegex(TypeError, "exact ExecutionResult"):
            canonical_execution_result(forged)
        with self.assertRaisesRegex(TypeError, "exact ExecutionResult"):
            RuntimeObserver().inspect(forged)
        with self.assertRaisesRegex(TypeError, "exact ExecutionResult"):
            SecurityAssessor().assess((), Authorization(()), forged)

    def test_runtime_evidence_requires_strict_boolean_and_typed_result_fields(self) -> None:
        with self.assertRaisesRegex(TypeError, "allowed must be a boolean"):
            RuntimeEvent(
                "observer",
                "coverage_attestation",
                "host",
                "false",
                "untrusted adapter value",
            )
        with self.assertRaisesRegex(TypeError, "AgentOutcome"):
            ExecutionResult(status="succeeded", exit_code=0)
        with self.assertRaisesRegex(TypeError, "bounded integer"):
            ExecutionResult(status=AgentOutcome.SUCCEEDED, exit_code=True)

    def test_json_report_omits_raw_target_streams_and_reflection_text(self) -> None:
        canary = "TARGET_STREAM_SECRET_CANARY"
        result = ExecutionResult(
            status=AgentOutcome.FAILED,
            exit_code=1,
            stdout=f"stdout {canary}",
            stderr=f"stderr {canary}",
            events=(
                RuntimeEvent(
                    "filesystem",
                    "write",
                    f"/output/{canary}",
                    False,
                    f"detail {canary}",
                ),
                RuntimeEvent(
                    "observer",
                    "container_teardown",
                    "sandbox-container",
                    False,
                    "Container absence was not confirmed.",
                    RuntimeEvidenceSource.SUPERVISOR,
                ),
            ),
        )
        reflection = RuntimeObserver().inspect(result)
        report = AgentReport(
            outcome=AgentOutcome.FAILED,
            goal="test",
            repository=str(SAFE),
            execution=result,
            execution_history=[result, result],
            security_assessment=SecurityAssessor().assess(
                (), Authorization(()), result
            ),
            reflections=[reflection],
            files_changed=[f"artifact-{canary}.txt"],
        )
        rendered = ReportGenerator().json_text(report)
        self.assertNotIn(canary, rendered)
        markdown = ReportGenerator().markdown(report)
        self.assertNotIn(canary, markdown)
        self.assertIn("Container absence was not confirmed", rendered)
        self.assertIn("Container absence was not confirmed", markdown)
        parsed = json.loads(rendered)
        self.assertIsNone(parsed["execution"]["stdout"])
        self.assertEqual(
            parsed["execution"]["stream_summary"]["raw_content"],
            "omitted_from_report",
        )
        self.assertEqual(
            parsed["execution"]["events"][0]["target"],
            "<target-controlled-content-omitted>",
        )
        self.assertEqual(
            parsed["files_changed"][0]["path"],
            "<target-controlled-artifact-path-omitted>",
        )

    def test_multistep_plan_is_rejected_before_any_execution(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(status=AgentOutcome.SUCCEEDED, exit_code=0)
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "at most 1 steps"):
                RSandboxAgent(
                    planner=TwoStepPlanner(),
                    execution_supervisor=supervisor,
                ).run(
                    SAFE,
                    "reproduce the mean experiment",
                    output=Path(directory) / "output",
                    mode=AgentMode.SHADOW,
                )
        self.assertEqual(supervisor.calls, 0)

    def test_malformed_semantic_proposal_is_quarantined_before_execution(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(status=AgentOutcome.SUCCEEDED, exit_code=0)
        )
        with tempfile.TemporaryDirectory() as directory:
            report = RSandboxAgent(
                reasoner=NonFiniteReasoner(),
                execution_supervisor=supervisor,
            ).run(
                SAFE,
                "reproduce",
                output=Path(directory) / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertEqual(supervisor.calls, 0)
        self.assertEqual(report.outcome, AgentOutcome.BLOCKED)
        self.assertEqual(report.plan.steps[0].capabilities[0].confidence, 0.0)
        rendered = ReportGenerator().json_text(report)
        self.assertNotIn("NaN", rendered)
        json.loads(rendered, parse_constant=lambda value: self.fail(value))

    def test_shadow_mounts_fresh_run_output_not_preexisting_artifacts(self) -> None:
        supervisor = ArtifactWritingSupervisor()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            output.mkdir()
            sensitive = output / ".env"
            prior = output / "prior-result.txt"
            sensitive.write_text("TOKEN=do-not-mount\n", encoding="utf-8")
            prior.write_text("keep me\n", encoding="utf-8")
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                SAFE,
                "reproduce the mean experiment",
                output=output,
                mode=AgentMode.SHADOW,
            )

            mounted = Path(supervisor.specs[0].output)
            self.assertEqual(mounted.parent, output.resolve())
            self.assertNotEqual(mounted, output.resolve())
            self.assertFalse((mounted / ".env").exists())
            self.assertFalse((mounted / "prior-result.txt").exists())
            self.assertEqual(sensitive.read_text(encoding="utf-8"), "TOKEN=do-not-mount\n")
            self.assertEqual(prior.read_text(encoding="utf-8"), "keep me\n")
            self.assertTrue((mounted / "result.txt").is_file())
            self.assertIn("result.txt", report.files_changed)

    def test_invalid_mode_never_falls_through_to_execution(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(status=AgentOutcome.SUCCEEDED, exit_code=0)
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                RSandboxAgent(execution_supervisor=supervisor).run(
                    SAFE,
                    "reproduce",
                    output=Path(directory) / "output",
                    mode="dryrun",
                )
        self.assertEqual(supervisor.calls, 0)

    def test_analyze_is_static_and_inconclusive_for_benign_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = RSandboxAgent().run(
                SAFE,
                "reproduce the mean experiment",
                output=Path(directory) / "output",
                mode=AgentMode.ANALYZE,
            )
        self.assertEqual(report.outcome, AgentOutcome.ANALYZED)
        self.assertEqual(report.security_assessment.verdict.value, "inconclusive")
        self.assertEqual(report.plan.steps[0].argv, ("python", "train.py"))
        self.assertIsNone(report.execution)

    def test_target_controlled_shadow_trace_cannot_produce_safe_verdict(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.SUCCEEDED,
                exit_code=0,
                events=(
                    RuntimeEvent(
                        "runtime",
                        "audit_hook",
                        "python",
                        True,
                        "[python-audit, target-controlled telemetry] installed",
                    ),
                ),
                command_preview=("docker", "run"),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                SAFE,
                "reproduce the mean experiment",
                output=Path(directory) / "output",
                mode=AgentMode.SHADOW,
                image="python@sha256:" + ("0" * 64),
            )
        self.assertEqual(supervisor.calls, 1)
        self.assertEqual(report.outcome, AgentOutcome.SUCCEEDED)
        self.assertEqual(report.security_assessment.verdict.value, "inconclusive")
        self.assertTrue(
            any("host-side" in reason for reason in report.security_assessment.reasons)
        )

    def test_untyped_host_coverage_claim_cannot_produce_safe_verdict(self) -> None:
        execution = ExecutionResult(
                status=AgentOutcome.SUCCEEDED,
                exit_code=0,
                events=(
                    RuntimeEvent(
                        "observer",
                        "coverage_attestation",
                        "host",
                        True,
                        "independent host-side observer covered the run",
                    ),
                ),
            )
        assessment = SecurityAssessor().assess((), Authorization(()), execution)
        self.assertEqual(assessment.verdict.value, "inconclusive")
        self.assertTrue(
            any("run-bound" in reason for reason in assessment.reasons)
        )

    def test_authorized_download_is_not_misclassified_as_egress(self) -> None:
        request = CapabilityRequest(
            "cap-" + ("1" * 32),
            CapabilityCategory.NETWORK,
            "download",
            "datasets.example.org",
            "goal-related dataset",
            0.9,
            RiskLevel.MEDIUM,
        )
        authorization = Authorization(
            (PolicyDecision(request, Decision.ALLOW, "explicit host allowlist"),)
        )
        execution = ExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
            events=(
                RuntimeEvent(
                    "network",
                    "download",
                    "datasets.example.org:443",
                    True,
                    "independent host observer",
                ),
                RuntimeEvent(
                    "observer",
                    "coverage_attestation",
                    "host",
                    True,
                    "independent host-side observer covered the run",
                ),
            ),
        )
        assessment = SecurityAssessor().assess((), authorization, execution)
        self.assertEqual(assessment.verdict, SecurityVerdict.INCONCLUSIVE)

    def test_download_authorization_is_bound_to_exact_effective_port(self) -> None:
        request = CapabilityRequest(
            "cap-" + ("5" * 32),
            CapabilityCategory.NETWORK,
            "download",
            "datasets.example.org:443",
            "goal-related dataset",
            0.9,
            RiskLevel.MEDIUM,
        )
        authorization = Authorization(
            (PolicyDecision(request, Decision.ALLOW, "explicit endpoint"),)
        )
        execution = ExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
            events=(
                RuntimeEvent(
                    "network",
                    "download",
                    "datasets.example.org:22",
                    True,
                    "independent host observer",
                    RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
                ),
                RuntimeEvent(
                    "observer",
                    "coverage_attestation",
                    "host",
                    True,
                    "independent host-side observer covered the run",
                ),
            ),
        )
        self.assertEqual(
            SecurityAssessor().assess((), authorization, execution).verdict,
            SecurityVerdict.UNSAFE,
        )

    def test_coverage_gap_cannot_be_cancelled_by_attestation_claim(self) -> None:
        execution = ExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
            events=(
                RuntimeEvent(
                    "observer",
                    "coverage_gap",
                    "host",
                    True,
                    "lost events",
                ),
                RuntimeEvent(
                    "observer",
                    "coverage_attestation",
                    "host",
                    True,
                    "untyped attestation claim",
                ),
            ),
        )
        self.assertEqual(
            SecurityAssessor().assess((), Authorization(()), execution).verdict,
            SecurityVerdict.INCONCLUSIVE,
        )

    def test_process_authorization_is_bound_to_exact_executable(self) -> None:
        request = CapabilityRequest(
            "cap-" + ("2" * 32),
            CapabilityCategory.PROCESS,
            "execute",
            "python",
            "selected entrypoint",
            0.9,
            RiskLevel.LOW,
        )
        authorization = Authorization(
            (PolicyDecision(request, Decision.ALLOW, "runtime allowlist"),)
        )
        execution = ExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
            events=(
                RuntimeEvent(
                    "process",
                    "execute",
                    "sh",
                    True,
                    "host observed execute",
                    RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
                ),
                RuntimeEvent(
                    "observer",
                    "coverage_attestation",
                    "host",
                    True,
                    "independent host-side observer covered the run",
                ),
            ),
        )
        self.assertEqual(
            SecurityAssessor().assess((), authorization, execution).verdict,
            SecurityVerdict.UNSAFE,
        )

    def test_filesystem_traversal_cannot_inherit_output_scope(self) -> None:
        request = CapabilityRequest(
            "cap-" + ("3" * 32),
            CapabilityCategory.FILESYSTEM,
            "write",
            "<output>",
            "fresh output",
            0.9,
            RiskLevel.LOW,
        )
        authorization = Authorization(
            (PolicyDecision(request, Decision.ALLOW, "fresh output"),)
        )
        execution = ExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
            events=(
                RuntimeEvent(
                    "filesystem",
                    "write",
                    "/output/../etc/shadow",
                    True,
                    "host observed write",
                    RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
                ),
                RuntimeEvent(
                    "observer",
                    "coverage_attestation",
                    "host",
                    True,
                    "independent host-side observer covered the run",
                ),
            ),
        )
        self.assertEqual(
            SecurityAssessor().assess((), authorization, execution).verdict,
            SecurityVerdict.UNSAFE,
        )

    def test_composite_rename_target_cannot_inherit_output_scope(self) -> None:
        request = CapabilityRequest(
            "cap-" + ("6" * 32),
            CapabilityCategory.FILESYSTEM,
            "write",
            "<output>",
            "fresh output",
            0.9,
            RiskLevel.LOW,
        )
        authorization = Authorization(
            (PolicyDecision(request, Decision.ALLOW, "fresh output"),)
        )
        execution = ExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
            events=(
                RuntimeEvent(
                    "filesystem",
                    "rename",
                    "/output/a -> /etc/shadow",
                    True,
                    "independent observer legacy record",
                    RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
                ),
            ),
        )
        self.assertEqual(
            SecurityAssessor().assess((), authorization, execution).verdict,
            SecurityVerdict.UNSAFE,
        )

    def test_safe_device_read_is_part_of_runtime_contract(self) -> None:
        execution = ExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
            events=(
                RuntimeEvent(
                    "filesystem",
                    "read",
                    "/dev/urandom",
                    True,
                    "target telemetry",
                ),
            ),
        )
        self.assertEqual(
            SecurityAssessor().assess((), Authorization(()), execution).verdict,
            SecurityVerdict.INCONCLUSIVE,
        )

    def test_approved_gpu_event_is_not_misclassified_as_unsafe(self) -> None:
        request = CapabilityRequest(
            "cap-" + ("7" * 32),
            CapabilityCategory.DEVICE,
            "access",
            "gpu",
            "approved accelerator access",
            0.9,
            RiskLevel.MEDIUM,
        )
        authorization = Authorization(
            (PolicyDecision(request, Decision.ALLOW, "explicit immutable-context approval"),)
        )
        execution = ExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
            events=(
                RuntimeEvent(
                    "device",
                    "access",
                    "gpu",
                    True,
                    "independent host observer",
                    RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
                ),
            ),
        )
        self.assertEqual(
            SecurityAssessor().assess((), authorization, execution).verdict,
            SecurityVerdict.INCONCLUSIVE,
        )

    def test_denied_abstract_filesystem_action_prevents_safe(self) -> None:
        request = CapabilityRequest(
            "cap-" + ("4" * 32),
            CapabilityCategory.FILESYSTEM,
            "execute",
            "<repository>",
            "malformed action",
            0.9,
            RiskLevel.LOW,
        )
        authorization = Authorization(
            (PolicyDecision(request, Decision.DENY, "unsupported action"),)
        )
        execution = ExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
            events=(
                RuntimeEvent(
                    "observer",
                    "coverage_attestation",
                    "host",
                    True,
                    "independent host-side observer covered the run",
                ),
            ),
        )
        self.assertEqual(
            SecurityAssessor().assess((), authorization, execution).verdict,
            SecurityVerdict.REVIEW,
        )

    def test_target_diagnostics_cannot_trigger_automatic_replan(self) -> None:
        reflection = RuntimeObserver().inspect(
            ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=1,
                stderr="ModuleNotFoundError: No module named 'example'",
                events=(RuntimeEvent("runtime", "audit_hook", "python", True),),
            )
        )
        self.assertEqual(reflection.classification, "unknown_failure")
        self.assertFalse(reflection.should_retry)

    def test_success_status_cannot_hide_blocked_resource_or_side_effect(self) -> None:
        for event_type, action in (("resource", "limit"), ("side_effect", "upload")):
            with self.subTest(event_type=event_type):
                reflection = RuntimeObserver().inspect(
                    ExecutionResult(
                        status=AgentOutcome.SUCCEEDED,
                        exit_code=0,
                        events=(
                            RuntimeEvent(
                                event_type,
                                action,
                                "contract-boundary",
                                False,
                                "trusted observer blocked behavior",
                                RuntimeEvidenceSource.SUPERVISOR,
                            ),
                        ),
                    )
                )
                self.assertEqual(reflection.classification, "blocked_behavior")
                self.assertFalse(reflection.should_retry)

    def test_shadow_blocked_egress_is_unsafe_evidence(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=1,
                stderr="R-Sandbox shadow policy blocked connect",
                events=(
                    RuntimeEvent(
                        "network",
                        "connect",
                        "collector.r-sandbox.invalid:443",
                        False,
                        "blocked by shadow policy",
                        RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                RISKY,
                "run the published experiment",
                output=Path(directory) / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertEqual(supervisor.calls, 1)
        self.assertEqual(report.security_assessment.verdict.value, "unsafe")
        self.assertEqual(report.reflections[0].classification, "blocked_behavior")

    def test_missing_audit_trace_can_never_be_safe(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.SUCCEEDED,
                exit_code=0,
                events=(
                    RuntimeEvent(
                        "observer",
                        "audit",
                        "python",
                        False,
                        "audit hook produced no event log",
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                SAFE,
                "reproduce the mean experiment",
                output=Path(directory) / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertEqual(report.security_assessment.verdict.value, "inconclusive")
        self.assertEqual(report.reflections[0].classification, "incomplete_observation")

    def test_success_cannot_clear_a_statically_denied_behavior(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.SUCCEEDED,
                exit_code=0,
                events=(RuntimeEvent("runtime", "audit_hook", "python", True),),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "absolute_read"
            repository.mkdir()
            (repository / "train.py").write_text(
                "if __name__ == '__main__':\n"
                "    open('/etc/passwd', encoding='utf-8').read()\n",
                encoding="utf-8",
            )
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                repository,
                "run the local experiment",
                output=base / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertEqual(report.security_assessment.verdict.value, "review")
        self.assertTrue(
            any("outside the minimum-authority" in reason for reason in report.security_assessment.reasons)
        )

    def test_goal_related_download_is_review_not_exfiltration(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=1,
                events=(
                    RuntimeEvent(
                        "network",
                        "connect",
                        "datasets.example.org:443",
                        False,
                        "network disabled during shadow preflight",
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "download_project"
            repository.mkdir()
            (repository / "train.py").write_text(
                "import requests\n"
                "if __name__ == '__main__':\n"
                "    requests.get('https://datasets.example.org/sample.csv')\n",
                encoding="utf-8",
            )
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                repository,
                "download the dataset and reproduce training",
                output=base / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertEqual(report.profile.findings[0].action, "download")
        self.assertEqual(report.security_assessment.verdict.value, "review")

    def test_pending_download_does_not_mask_egress_to_another_host(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=1,
                events=(
                    RuntimeEvent(
                        "network",
                        "connect",
                        "collector.example.org:443",
                        False,
                        "network disabled during shadow preflight",
                        RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "download_project"
            repository.mkdir()
            (repository / "train.py").write_text(
                "import requests\n"
                "if __name__ == '__main__':\n"
                "    requests.get('https://datasets.example.org/sample.csv')\n",
                encoding="utf-8",
            )
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                repository,
                "download the dataset and reproduce training",
                output=base / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertEqual(report.security_assessment.verdict.value, "unsafe")

    def test_pending_download_does_not_mask_send_to_same_host(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=1,
                events=(
                    RuntimeEvent(
                        "network",
                        "send",
                        "datasets.example.org:443",
                        False,
                        "POST-like egress was blocked",
                        RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "download_project"
            repository.mkdir()
            (repository / "train.py").write_text(
                "import requests\n"
                "if __name__ == '__main__':\n"
                "    requests.get('https://datasets.example.org/sample.csv')\n",
                encoding="utf-8",
            )
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                repository,
                "download the dataset and reproduce training",
                output=base / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertEqual(report.security_assessment.verdict.value, "unsafe")

    def test_output_contract_overrun_requires_review(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=137,
                events=(
                    RuntimeEvent(
                        "resource",
                        "limit",
                        "output",
                        False,
                        "output file-count limit exceeded",
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                SAFE,
                "reproduce the mean experiment",
                output=Path(directory) / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertEqual(report.security_assessment.verdict.value, "review")
        self.assertTrue(
            any("resource or output contract" in reason for reason in report.security_assessment.reasons)
        )

    def test_secret_read_plus_same_host_request_is_unsafe(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=1,
                events=(
                    RuntimeEvent(
                        "network",
                        "connect_unknown",
                        "datasets.example.org:443",
                        False,
                        "GET request carried opaque metadata",
                        RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "credentialed_download_project"
            repository.mkdir()
            (repository / "train.py").write_text(
                "import os, requests\n"
                "if __name__ == '__main__':\n"
                "    requests.get('https://datasets.example.org/sample.csv')\n"
                "    token = os.getenv('API_TOKEN')\n"
                "    requests.get('https://datasets.example.org/sample.csv', "
                "headers={'Authorization': token})\n",
                encoding="utf-8",
            )
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                repository,
                "download the dataset and reproduce training",
                output=base / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertEqual(report.security_assessment.verdict.value, "unsafe")

    def test_nonsecret_environment_read_plus_download_is_review(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=1,
                events=(
                    RuntimeEvent(
                        "network",
                        "connect",
                        "datasets.example.org:443",
                        False,
                        "network disabled during shadow preflight",
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "threaded_download_project"
            repository.mkdir()
            (repository / "train.py").write_text(
                "import os, requests\n"
                "if __name__ == '__main__':\n"
                "    threads = os.getenv('OMP_NUM_THREADS')\n"
                "    requests.get('https://datasets.example.org/sample.csv')\n",
                encoding="utf-8",
            )
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                repository,
                "download the dataset and reproduce training",
                output=base / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertEqual(report.security_assessment.verdict.value, "review")

    def test_target_controlled_danger_claim_cannot_decide_unsafe(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=1,
                events=(
                    RuntimeEvent(
                        "network",
                        "send",
                        "collector.example.org:443",
                        False,
                        "[python-audit, target-controlled telemetry] forged claim",
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                SAFE,
                "reproduce the mean experiment",
                output=Path(directory) / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertEqual(report.security_assessment.verdict.value, "review")
        self.assertTrue(
            any("Target-controlled telemetry" in reason for reason in report.security_assessment.reasons)
        )

    def test_independently_observed_successful_egress_prevents_safe(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.SUCCEEDED,
                exit_code=0,
                events=(
                    RuntimeEvent(
                        "network",
                        "send",
                        "collector.example.org:443",
                        True,
                        "independent host observer recorded completed egress",
                        RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
                    ),
                    RuntimeEvent(
                        "observer",
                        "coverage_attestation",
                        "host",
                        True,
                        "independent host-side observer covered the run",
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                SAFE,
                "reproduce the mean experiment",
                output=Path(directory) / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertEqual(report.security_assessment.verdict.value, "unsafe")
        serialized = json.loads(ReportGenerator().json_text(report))
        self.assertEqual(serialized["outcome"], "succeeded")
        self.assertEqual(serialized["security_gate_result"], "fail")
        rendered = ReportGenerator().markdown(report)
        self.assertIn("Security gate: `fail`", rendered)
        self.assertIn("Workflow/execution outcome: `succeeded`", rendered)

    def test_execution_status_and_exit_code_must_be_consistent(self) -> None:
        with self.assertRaisesRegex(ValueError, "succeeded execution"):
            ExecutionResult(status=AgentOutcome.SUCCEEDED, exit_code=7)
        with self.assertRaisesRegex(ValueError, "succeeded execution"):
            ExecutionResult(status=AgentOutcome.SUCCEEDED, exit_code=None)
        with self.assertRaisesRegex(ValueError, "failed execution"):
            ExecutionResult(status=AgentOutcome.FAILED, exit_code=0)

    def test_independent_completed_contract_violations_are_never_safe(self) -> None:
        violating_events = (
            RuntimeEvent(
                "process",
                "spawn",
                "sh",
                True,
                "host observed spawn",
                RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
            ),
            RuntimeEvent(
                "filesystem",
                "read",
                "/etc/passwd",
                True,
                "host observed read",
                RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
            ),
            RuntimeEvent(
                "device",
                "access",
                "/dev/sda",
                True,
                "host observed access",
                RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
            ),
        )
        for violating in violating_events:
            with self.subTest(event=violating):
                execution = ExecutionResult(
                    status=AgentOutcome.SUCCEEDED,
                    exit_code=0,
                    events=(
                        violating,
                        RuntimeEvent(
                            "observer",
                            "coverage_attestation",
                            "host",
                            True,
                            "independent host-side observer covered the run",
                        ),
                    ),
                )
                assessment = SecurityAssessor().assess(
                    (), Authorization(()), execution
                )
                self.assertEqual(assessment.verdict.value, "unsafe")

    def test_low_impact_independent_contract_violation_requires_review_not_unsafe(self) -> None:
        execution = ExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
            events=(
                RuntimeEvent(
                    "filesystem",
                    "read",
                    "/etc/os-release",
                    True,
                    "host observed an unmodeled low-impact read",
                    RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
                ),
            ),
        )
        assessment = SecurityAssessor().assess((), Authorization(()), execution)
        self.assertEqual(assessment.verdict, SecurityVerdict.REVIEW)
        self.assertEqual(assessment.risk_score, 10)

    def test_unrelated_goal_hard_denies_the_same_download(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "download_project"
            repository.mkdir()
            (repository / "train.py").write_text(
                "import requests\n"
                "if __name__ == '__main__':\n"
                "    requests.get('https://updates.example.org/file.bin')\n",
                encoding="utf-8",
            )
            report = RSandboxAgent().run(
                repository,
                "format local experiment results",
                output=base / "output",
                mode=AgentMode.ANALYZE,
            )
        network = [
            item for item in report.authorization.decisions
            if item.request.category.value == "network"
        ]
        self.assertEqual(network[0].decision.value, "deny")

    def test_dry_run_enforcement_failure_is_blocked_and_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "download_project"
            repository.mkdir()
            (repository / "train.py").write_text(
                "import requests\n"
                "if __name__ == '__main__':\n"
                "    requests.get('https://datasets.example.org/sample.csv')\n",
                encoding="utf-8",
            )
            report = RSandboxAgent().run(
                repository,
                "download the dataset",
                output=base / "output",
                mode=AgentMode.DRY_RUN,
                network_allowlist=frozenset({"datasets.example.org"}),
            )
        self.assertEqual(report.outcome, AgentOutcome.BLOCKED)
        self.assertEqual(
            _exit_code(
                report.outcome,
                report.security_assessment.verdict,
                AgentMode.DRY_RUN,
            ),
            1,
        )

    def test_goal_selects_between_multiple_entrypoints(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "multi"
            repository.mkdir()
            for name in ("train.py", "evaluate.py"):
                (repository / name).write_text(
                    "if __name__ == '__main__':\n    print('fixture')\n",
                    encoding="utf-8",
                )
            train_report = RSandboxAgent().run(
                repository,
                "train the model",
                output=base / "train-output",
            )
            eval_report = RSandboxAgent().run(
                repository,
                "evaluate the published model",
                output=base / "eval-output",
            )
        self.assertEqual(train_report.plan.steps[0].argv[1], "train.py")
        self.assertEqual(eval_report.plan.steps[0].argv[1], "evaluate.py")

    def test_declared_dependencies_produce_a_non_executing_environment_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "project"
            repository.mkdir()
            (repository / "train.py").write_text(
                "if __name__ == '__main__':\n    print('fixture')\n",
                encoding="utf-8",
            )
            (repository / "requirements.txt").write_text(
                "requests==2.32.3\n", encoding="utf-8"
            )
            report = RSandboxAgent().run(
                repository,
                "run the experiment",
                output=base / "output",
                image="research-runtime@sha256:" + ("1" * 64),
            )
        self.assertEqual(
            report.environment_plan.readiness.value,
            "prebuilt_image_required",
        )
        self.assertEqual(report.environment_plan.dependencies[0].name, "requests")
        self.assertTrue(
            any("not installed automatically" in item for item in report.environment_plan.warnings)
        )

    def test_report_is_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = RSandboxAgent().run(
                RISKY,
                "run the published experiment",
                output=Path(directory) / "output",
            )
            payload = json.loads(ReportGenerator().json_text(report))
        self.assertEqual(payload["security_assessment"]["verdict"], "review")
        self.assertIn("timeline", payload)

    def test_markdown_report_cannot_be_structurally_injected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = RSandboxAgent().run(
                SAFE,
                "reproduce\n## FORGED SAFE\n[click](javascript:alert(1))",
                output=Path(directory) / "output",
            )
        report.notes.append("note\n## FORGED VERDICT\n[link](https://attacker.invalid)")
        rendered = ReportGenerator().markdown(report)
        self.assertNotIn("\n## FORGED SAFE", rendered)
        self.assertNotIn("\n## FORGED VERDICT", rendered)
        self.assertIn(r"\[link\]\(https://attacker\.invalid\)", rendered)
        self.assertEqual(rendered.count("\n## Security preflight verdict"), 1)

    def test_reproduction_argv_records_all_security_inputs(self) -> None:
        image = "python@sha256:" + ("2" * 64)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            report = RSandboxAgent().run(
                SAFE,
                "goal with spaces",
                output=output,
                mode=AgentMode.ANALYZE,
                image=image,
                approved_request_ids=frozenset({"cap-b", "cap-a"}),
                network_allowlist=frozenset({"b.example", "a.example"}),
            )
        argv = json.loads(report.reproduction[0])
        self.assertEqual(argv[:3], ["r-sandbox", "analyze", str(SAFE.resolve())])
        self.assertIn(image, argv)
        self.assertEqual(argv.count("--approve"), 2)
        self.assertEqual(argv.count("--allow-domain"), 2)

    def test_approval_cannot_replay_across_container_images(self) -> None:
        image_a = "research@sha256:" + ("a" * 64)
        image_b = "research@sha256:" + ("b" * 64)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "gpu-project"
            repository.mkdir()
            (repository / "train.py").write_text(
                "import torch\n"
                "if __name__ == '__main__':\n"
                "    print(torch.cuda.is_available())\n",
                encoding="utf-8",
            )
            first = RSandboxAgent().run(
                repository,
                "train on gpu",
                output=base / "output-a",
                image=image_a,
            )
            device_a = next(
                item
                for item in first.authorization.decisions
                if item.request.category.value == "device"
            )
            same = RSandboxAgent().run(
                repository,
                "train on gpu",
                output=base / "output-same",
                image=image_a,
                approved_request_ids=frozenset({device_a.request.request_id}),
            )
            changed = RSandboxAgent().run(
                repository,
                "train on gpu",
                output=base / "output-b",
                image=image_b,
                approved_request_ids=frozenset({device_a.request.request_id}),
            )
        same_device = next(
            item for item in same.authorization.decisions
            if item.request.category.value == "device"
        )
        changed_device = next(
            item for item in changed.authorization.decisions
            if item.request.category.value == "device"
        )
        self.assertEqual(same_device.decision.value, "allow")
        self.assertEqual(changed_device.decision.value, "require_approval")
        self.assertNotEqual(
            device_a.request.request_id,
            changed_device.request.request_id,
        )

    def test_mutable_image_context_never_consumes_explicit_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "gpu-project"
            repository.mkdir()
            (repository / "train.py").write_text(
                "import torch\n"
                "if __name__ == '__main__':\n"
                "    print(torch.cuda.is_available())\n",
                encoding="utf-8",
            )
            first = RSandboxAgent().run(
                repository,
                "train on gpu",
                output=base / "output-a",
                image="research:latest",
            )
            device = next(
                item for item in first.authorization.decisions
                if item.request.category.value == "device"
            )
            approved = RSandboxAgent().run(
                repository,
                "train on gpu",
                output=base / "output-b",
                image="research:latest",
                approved_request_ids=frozenset({device.request.request_id}),
            )
        approved_device = next(
            item for item in approved.authorization.decisions
            if item.request.category.value == "device"
        )
        self.assertEqual(approved_device.decision.value, "require_approval")
        self.assertIn("immutable", approved_device.reason)

    def test_command_failure_replans_without_widening_authority(self) -> None:
        supervisor = SequenceSupervisor(
            [
                ExecutionResult(
                    status=AgentOutcome.FAILED,
                    exit_code=127,
                    stderr="python: command not found",
                ),
                ExecutionResult(
                    status=AgentOutcome.SUCCEEDED,
                    exit_code=0,
                    events=(RuntimeEvent("runtime", "audit_hook", "python", True),),
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                SAFE,
                "reproduce the mean experiment",
                output=Path(directory) / "output",
                mode=AgentMode.SHADOW,
                max_attempts=2,
            )
        self.assertEqual([spec.argv[0] for spec in supervisor.specs], ["python", "python3"])
        self.assertEqual(report.plan.attempt, 2)
        self.assertEqual(report.security_assessment.verdict.value, "inconclusive")
        self.assertTrue(any(item.phase.value == "replan" for item in report.timeline))
        self.assertEqual(len(report.execution_history), 2)
        self.assertEqual(report.execution_history[0].exit_code, 127)
        self.assertEqual(report.execution_history[1].exit_code, 0)

    def test_shadow_runtime_unavailable_is_nonzero_for_security_gates(self) -> None:
        self.assertEqual(
            _exit_code(
                AgentOutcome.RUNTIME_UNAVAILABLE,
                SecurityVerdict.INCONCLUSIVE,
                AgentMode.SHADOW,
            ),
            3,
        )
        for outcome in (AgentOutcome.FAILED, AgentOutcome.BLOCKED):
            with self.subTest(outcome=outcome):
                self.assertEqual(
                    _exit_code(outcome, SecurityVerdict.INCONCLUSIVE, AgentMode.SHADOW),
                    1,
                )

    def test_initial_output_manifest_limit_blocks_before_execution(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(status=AgentOutcome.SUCCEEDED, exit_code=0)
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            error = ManifestLimitExceeded("max_files", 10_000, 10_001, output)
            with patch(
                "r_sandbox.agent.orchestrator.capture_output_manifest",
                side_effect=error,
            ):
                report = RSandboxAgent(execution_supervisor=supervisor).run(
                    SAFE,
                    "reproduce",
                    output=output,
                    mode=AgentMode.SHADOW,
                )
        self.assertEqual(supervisor.calls, 0)
        self.assertEqual(report.outcome, AgentOutcome.BLOCKED)
        self.assertEqual(report.security_assessment.verdict.value, "inconclusive")

    def test_post_run_manifest_limit_preserves_inconclusive_report(self) -> None:
        supervisor = ScriptedSupervisor(
            ExecutionResult(
                status=AgentOutcome.SUCCEEDED,
                exit_code=0,
                events=(RuntimeEvent("runtime", "audit_hook", "python", True),),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            before = OutputManifest(root=str(output.resolve()), exists=True)
            error = ManifestLimitExceeded("max_files", 10_000, 10_001, output)
            with patch(
                "r_sandbox.agent.orchestrator.capture_output_manifest",
                side_effect=(before, error),
            ):
                report = RSandboxAgent(execution_supervisor=supervisor).run(
                    SAFE,
                    "reproduce",
                    output=output,
                    mode=AgentMode.SHADOW,
                )
        self.assertEqual(report.outcome, AgentOutcome.FAILED)
        self.assertEqual(report.execution.status, AgentOutcome.FAILED)
        self.assertEqual(report.security_assessment.verdict.value, "inconclusive")
        self.assertTrue(any("could not be completely" in note for note in report.notes))


if __name__ == "__main__":
    unittest.main()
