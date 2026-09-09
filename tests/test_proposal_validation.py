from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from r_sandbox.models import (
    CapabilityCategory,
    CapabilityRequest,
    Decision,
    Evidence,
    AgentOutcome,
    AgentReport,
    ExecutionPlan,
    PlanStep,
    RiskLevel,
)
from r_sandbox.policy import PolicyConfig, PolicyEngine, capability_request_id
from r_sandbox.policy.proposal_validation import MAX_PLAN_STEPS
from r_sandbox.agent.reporter import ReportGenerator
from r_sandbox.agent.security_assessor import SecurityAssessor


ROOT = Path(__file__).resolve().parents[1]
SAFE = ROOT / "examples" / "safe_research_repo"
GOAL = "test"


def capability(
    *,
    category: CapabilityCategory = CapabilityCategory.PROCESS,
    action: str = "execute",
    target: str = "python",
    risk: RiskLevel = RiskLevel.LOW,
    confidence: float = 0.9,
    justification: str = "bounded test proposal",
    evidence: tuple[Evidence, ...] = (),
) -> CapabilityRequest:
    request_id = capability_request_id(
        SAFE,
        GOAL,
        category,
        action,
        target,
        risk,
        confidence,
        justification=justification,
        evidence=evidence,
    )
    return CapabilityRequest(
        request_id,
        category,
        action,
        target,
        justification,
        confidence,
        risk,
        evidence,
    )


def proposal(*requests: CapabilityRequest) -> ExecutionPlan:
    return ExecutionPlan(
        GOAL,
        "strict validation test",
        (PlanStep("step-1", "run test", ("python", "train.py"), capabilities=requests),),
    )


class ProposalValidationTests(unittest.TestCase):
    def test_capability_request_subclass_is_rejected_at_policy_boundary(self) -> None:
        class SwitchingCapabilityRequest(CapabilityRequest):
            pass

        base = capability()
        malicious = SwitchingCapabilityRequest(
            base.request_id,
            base.category,
            base.action,
            base.target,
            base.justification,
            base.confidence,
            base.risk,
            base.evidence,
        )
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            ValueError, "must be CapabilityRequest"
        ):
            PolicyEngine().authorize(
                proposal(malicious),
                PolicyConfig(SAFE, Path(directory) / "output"),
            )

    def test_authorization_retains_a_detached_request_snapshot(self) -> None:
        original = capability()
        with tempfile.TemporaryDirectory() as directory:
            authorization = PolicyEngine().authorize(
                proposal(original),
                PolicyConfig(SAFE, Path(directory) / "output"),
            )
        self.assertIsNot(authorization.decisions[0].request, original)
        self.assertEqual(authorization.decisions[0].request, original)

    def test_wrong_capability_enum_types_raise_before_config_normalization(self) -> None:
        valid = capability()
        malformed = (
            replace(valid, category="process"),
            replace(valid, risk="low"),
        )
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-repository"
            for request in malformed:
                with self.subTest(request=request), self.assertRaisesRegex(
                    ValueError, "invalid enum type"
                ):
                    PolicyEngine().authorize(
                        proposal(request),
                        PolicyConfig(missing, Path(directory) / "output"),
                    )

    def test_invalid_request_strings_deny_entire_plan_without_host_lookup(self) -> None:
        valid = capability()
        malformed = (
            capability(target="/output/bad\x00name"),
            capability(justification="x" * 16_385),
            replace(
                valid,
                request_id="cap-11111111111111111111111111111111",
                target="/output/bad-\udcff-name",
            ),
            replace(valid, request_id="CAP-not-canonical"),
        )
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-repository"
            for request in malformed:
                with self.subTest(request=request):
                    authorization = PolicyEngine().authorize(
                        proposal(valid, request),
                        PolicyConfig(missing, Path(directory) / "output"),
                    )
                    self.assertEqual(len(authorization.decisions), 2)
                    self.assertTrue(
                        all(item.decision == Decision.DENY for item in authorization.decisions)
                    )
                    self.assertIn("Malformed capability", authorization.decisions[1].reason)
                    self.assertIn("aborted", authorization.decisions[0].reason)
                    quarantined = authorization.decisions[1].request
                    self.assertEqual(quarantined.action, "invalid_proposal")
                    self.assertEqual(quarantined.target, "<malformed-capability>")

    def test_non_string_request_field_raises_before_config_normalization(self) -> None:
        malformed = replace(capability(), action=None)
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-repository"
            with self.assertRaisesRegex(ValueError, "action must be a string"):
                PolicyEngine().authorize(
                    proposal(malformed),
                    PolicyConfig(missing, Path(directory) / "output"),
                )

    def test_boolean_and_nonfinite_confidence_are_denied(self) -> None:
        valid = capability()
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-repository"
            for value in (
                True,
                float("nan"),
                float("inf"),
                float("-inf"),
                10**1000,
            ):
                with self.subTest(value=value):
                    authorization = PolicyEngine().authorize(
                        proposal(replace(valid, confidence=value)),
                        PolicyConfig(missing, Path(directory) / "output"),
                    )
                    self.assertEqual(authorization.decisions[0].decision, Decision.DENY)
                    self.assertIn("finite non-boolean", authorization.decisions[0].reason)

    def test_huge_numeric_policy_ceiling_is_denied_without_overflow(self) -> None:
        valid = capability()
        with tempfile.TemporaryDirectory() as directory:
            authorization = PolicyEngine().authorize(
                proposal(valid),
                PolicyConfig(
                    SAFE,
                    Path(directory) / "output",
                    max_memory_mb=10**1000,
                ),
            )
        self.assertEqual(authorization.decisions[0].decision, Decision.DENY)
        self.assertIn("Policy ceiling", authorization.decisions[0].reason)

    def test_malformed_evidence_shape_raises_before_config_normalization(self) -> None:
        valid = capability()
        malformed = (
            replace(valid, evidence=[Evidence("source.py", "detail")]),
            replace(valid, evidence=(object(),)),
        )
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-repository"
            for request in malformed:
                with self.subTest(request=request), self.assertRaisesRegex(
                    ValueError, "evidence"
                ):
                    PolicyEngine().authorize(
                        proposal(request),
                        PolicyConfig(missing, Path(directory) / "output"),
                    )

    def test_invalid_evidence_values_are_denied(self) -> None:
        base = capability(evidence=(Evidence("source.py", "detail", 1),))
        malformed = (
            replace(base, evidence=(Evidence("source.py", "detail", True),)),
            replace(base, evidence=(Evidence("source.py", "bad\x00detail", 1),)),
        )
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-repository"
            for request in malformed:
                with self.subTest(request=request):
                    authorization = PolicyEngine().authorize(
                        proposal(request),
                        PolicyConfig(missing, Path(directory) / "output"),
                    )
                    self.assertEqual(authorization.decisions[0].decision, Decision.DENY)
                    self.assertIn("evidence", authorization.decisions[0].reason)

    def test_quarantined_request_is_safe_for_assessor_and_reporters(self) -> None:
        malformed = replace(
            capability(
                category=CapabilityCategory.NETWORK,
                action="download",
                target="datasets.example.org",
                risk=RiskLevel.MEDIUM,
            ),
            action="download\x00then-send",
        )
        plan = proposal(malformed)
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-repository"
            authorization = PolicyEngine().authorize(
                plan,
                PolicyConfig(missing, Path(directory) / "output"),
            )
        quarantined = authorization.decisions[0].request
        self.assertEqual(quarantined.category, CapabilityCategory.NETWORK)
        self.assertEqual(quarantined.action, "invalid_proposal")
        self.assertNotIn("\x00", quarantined.target + quarantined.justification)

        assessment = SecurityAssessor().assess((), authorization, None)
        report = AgentReport(
            outcome=AgentOutcome.BLOCKED,
            goal=GOAL,
            repository=str(SAFE),
            plan=plan,
            authorization=authorization,
            security_assessment=assessment,
        )
        generator = ReportGenerator()
        self.assertIn("invalid_proposal", generator.markdown(report))
        parsed = json.loads(generator.json_text(report))
        self.assertEqual(
            parsed["authorization"]["decisions"][0]["request"]["action"],
            "invalid_proposal",
        )

    def test_oversized_and_wrong_container_plans_raise_without_host_lookup(self) -> None:
        step = PlanStep("step", "test", ("python", "train.py"))
        oversized = ExecutionPlan(
            GOAL,
            "too many steps",
            tuple(
                replace(step, step_id=f"step-{index}")
                for index in range(MAX_PLAN_STEPS + 1)
            ),
        )
        wrong_container = replace(proposal(capability()), steps=[step])
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-repository"
            config = PolicyConfig(missing, Path(directory) / "output")
            for plan in (oversized, wrong_container):
                with self.subTest(plan=plan), self.assertRaisesRegex(
                    ValueError, "Malformed execution plan"
                ):
                    PolicyEngine().authorize(plan, config)

    def test_duplicate_capability_ids_are_rejected_before_authorization(self) -> None:
        duplicated = capability()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "request ids must be unique"):
                PolicyEngine().authorize(
                    proposal(duplicated, duplicated),
                    PolicyConfig(SAFE, Path(directory) / "output"),
                )

    def test_secret_bearing_network_url_is_quarantined_before_reporting(self) -> None:
        canary = "NETWORK_SECRET_CANARY"
        network = capability(
            category=CapabilityCategory.NETWORK,
            action="download",
            target=f"https://user:{canary}@datasets.example.org/private?token={canary}",
            risk=RiskLevel.MEDIUM,
        )
        with tempfile.TemporaryDirectory() as directory:
            authorization = PolicyEngine().authorize(
                proposal(network),
                PolicyConfig(SAFE, Path(directory) / "output"),
            )
        self.assertEqual(authorization.decisions[0].decision, Decision.DENY)
        self.assertEqual(
            authorization.decisions[0].request.target,
            "<malformed-capability>",
        )
        assessment = SecurityAssessor().assess((), authorization, None)
        report = AgentReport(
            outcome=AgentOutcome.BLOCKED,
            goal=GOAL,
            repository=str(SAFE),
            authorization=authorization,
            security_assessment=assessment,
        )
        self.assertNotIn(canary, ReportGenerator().json_text(report))

    def test_fresh_output_mutation_is_allowed_before_sensitive_name_filter(self) -> None:
        output_delete = capability(
            category=CapabilityCategory.FILESYSTEM,
            action="delete_or_move",
            target="/output/.ssh/transient-artifact",
        )
        workspace_read = capability(
            category=CapabilityCategory.FILESYSTEM,
            action="read",
            target="/workspace/.ssh/id_rsa",
        )
        with tempfile.TemporaryDirectory() as directory:
            authorization = PolicyEngine().authorize(
                proposal(output_delete, workspace_read),
                PolicyConfig(SAFE, Path(directory) / "output"),
            )
        self.assertEqual(authorization.decisions[0].decision, Decision.ALLOW)
        self.assertIn("fresh per-run", authorization.decisions[0].reason)
        self.assertEqual(authorization.decisions[1].decision, Decision.DENY)
        self.assertIn("Credential", authorization.decisions[1].reason)


if __name__ == "__main__":
    unittest.main()
