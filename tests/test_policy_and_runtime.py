from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from r_sandbox.models import (
    AgentOutcome,
    CapabilityCategory,
    CapabilityRequest,
    Decision,
    ExecutionPlan,
    PlanStep,
    ResourceLimits,
    RiskLevel,
)
from r_sandbox.policy import (
    PolicyConfig,
    PolicyEngine,
    capability_authorization_context,
    capability_request_id,
)
from r_sandbox.tools.execution_supervisor import DryRunExecutionSupervisor
from r_sandbox.tools.sandbox_builder import (
    SandboxBuildError,
    SandboxBuilder,
    UnauthorizedCapabilityError,
)


ROOT = Path(__file__).resolve().parents[1]
SAFE = ROOT / "examples" / "safe_research_repo"


def request(
    _request_id: str,
    category: CapabilityCategory,
    action: str,
    target: str,
    risk: RiskLevel = RiskLevel.HIGH,
) -> CapabilityRequest:
    confidence = 0.9
    justification = "test evidence"
    request_id = capability_request_id(
        SAFE,
        "test",
        category,
        action,
        target,
        risk,
        confidence,
        justification=justification,
    )
    return CapabilityRequest(request_id, category, action, target, justification, confidence, risk)


def plan_for(*requests: CapabilityRequest) -> ExecutionPlan:
    return ExecutionPlan(
        "test",
        "test",
        (PlanStep("step", "test", ("python", "train.py"), capabilities=tuple(requests)),),
    )


def runtime_plan_for(*requests: CapabilityRequest) -> ExecutionPlan:
    required = (
        request("ignored", CapabilityCategory.FILESYSTEM, "read", "<repository>", RiskLevel.LOW),
        request("ignored", CapabilityCategory.FILESYSTEM, "read", "<output>", RiskLevel.LOW),
        request("ignored", CapabilityCategory.FILESYSTEM, "write", "<output>", RiskLevel.LOW),
        request("ignored", CapabilityCategory.FILESYSTEM, "read", "<temporary>", RiskLevel.LOW),
        request("ignored", CapabilityCategory.FILESYSTEM, "write", "<temporary>", RiskLevel.LOW),
        request("ignored", CapabilityCategory.FILESYSTEM, "read", "<shared-memory>", RiskLevel.LOW),
        request("ignored", CapabilityCategory.FILESYSTEM, "write", "<shared-memory>", RiskLevel.LOW),
        request("ignored", CapabilityCategory.RESOURCE, "cpu", "1", RiskLevel.LOW),
        request("ignored", CapabilityCategory.RESOURCE, "memory_mb", "1024", RiskLevel.LOW),
        request("ignored", CapabilityCategory.RESOURCE, "pids", "128", RiskLevel.LOW),
        request("ignored", CapabilityCategory.RESOURCE, "timeout_seconds", "300", RiskLevel.LOW),
        request("ignored", CapabilityCategory.RESOURCE, "output_mb", "1024", RiskLevel.LOW),
        request("ignored", CapabilityCategory.RESOURCE, "output_files", "10000", RiskLevel.LOW),
        request("ignored", CapabilityCategory.RESOURCE, "temporary_mb", "64", RiskLevel.LOW),
        request("ignored", CapabilityCategory.RESOURCE, "shared_memory_mb", "16", RiskLevel.LOW),
        request("ignored", CapabilityCategory.PROCESS, "execute", "python", RiskLevel.LOW),
    )
    combined = list(requests)
    seen = {item.request_id for item in combined}
    combined.extend(item for item in required if item.request_id not in seen)
    return plan_for(*combined)


class PolicyAndRuntimeTests(unittest.TestCase):
    def test_capability_mutation_after_authorization_cannot_change_runtime_grant(self) -> None:
        plan = runtime_plan_for()
        original = plan.steps[0].capabilities[0]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            authorization = PolicyEngine().authorize(plan, PolicyConfig(SAFE, output))
            object.__setattr__(original, "category", CapabilityCategory.DEVICE)
            object.__setattr__(original, "action", "access")
            object.__setattr__(original, "target", "gpu")
            with self.assertRaisesRegex(
                UnauthorizedCapabilityError,
                "payload differs",
            ):
                SandboxBuilder().build(
                    SAFE,
                    output,
                    plan.steps[0],
                    authorization,
                )
        self.assertEqual(
            authorization.decisions[0].request.category,
            CapabilityCategory.FILESYSTEM,
        )

    def test_capability_identity_rejects_unrepresentable_confidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "finite real"):
            capability_request_id(
                SAFE,
                "test",
                CapabilityCategory.NETWORK,
                "download",
                "datasets.example.org",
                RiskLevel.MEDIUM,
                10**1000,
            )

    def test_identity_boundaries_reject_lone_surrogate_api_text(self) -> None:
        with self.assertRaisesRegex(ValueError, "valid UTF-8"):
            capability_authorization_context("python:\udcff")
        with self.assertRaisesRegex(ValueError, "valid UTF-8"):
            capability_request_id(
                SAFE,
                "test \udcff",
                CapabilityCategory.NETWORK,
                "download",
                "datasets.example.org",
                RiskLevel.MEDIUM,
                0.9,
            )

    def test_network_allowlist_is_bound_to_effective_port(self) -> None:
        https_request = request(
            "ignored",
            CapabilityCategory.NETWORK,
            "download",
            "datasets.example.org",
            RiskLevel.MEDIUM,
        )
        ssh_request = request(
            "ignored",
            CapabilityCategory.NETWORK,
            "download",
            "datasets.example.org:22",
            RiskLevel.MEDIUM,
        )
        with tempfile.TemporaryDirectory() as directory:
            config = PolicyConfig(
                SAFE,
                Path(directory) / "output",
                network_allowlist=frozenset({"datasets.example.org"}),
            )
            https = PolicyEngine().authorize(plan_for(https_request), config)
            ssh = PolicyEngine().authorize(plan_for(ssh_request), config)
        self.assertEqual(https.decisions[0].decision, Decision.ALLOW)
        self.assertEqual(ssh.decisions[0].decision, Decision.REQUIRE_APPROVAL)

    def test_network_port_zero_is_hard_denied(self) -> None:
        network = request(
            "ignored",
            CapabilityCategory.NETWORK,
            "download",
            "datasets.example.org:0",
            RiskLevel.MEDIUM,
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                plan_for(network),
                PolicyConfig(SAFE, Path(directory) / "output"),
            )
        self.assertEqual(auth.decisions[0].decision, Decision.DENY)

    def test_approval_context_flag_requires_an_exact_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = PolicyConfig(
                SAFE,
                Path(directory) / "output",
                approval_context_immutable="false",
            )
            with self.assertRaisesRegex(ValueError, "exact boolean"):
                PolicyEngine().authorize(plan_for(), config)

    def test_network_nan_confidence_is_hard_denied_before_identity_check(self) -> None:
        network = replace(
            request(
                "ignored",
                CapabilityCategory.NETWORK,
                "download",
                "datasets.example.org",
                RiskLevel.MEDIUM,
            ),
            confidence=float("nan"),
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                plan_for(network),
                PolicyConfig(
                    SAFE,
                    Path(directory) / "output",
                    network_allowlist=frozenset({network.target}),
                ),
            )
        self.assertEqual(auth.decisions[0].decision, Decision.DENY)
        self.assertIn("finite", auth.decisions[0].reason)

    def test_device_nan_confidence_is_hard_denied_before_approval(self) -> None:
        device = replace(
            request(
                "ignored",
                CapabilityCategory.DEVICE,
                "access",
                "gpu",
                RiskLevel.MEDIUM,
            ),
            confidence=float("nan"),
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                plan_for(device),
                PolicyConfig(
                    SAFE,
                    Path(directory) / "output",
                    approved_request_ids=frozenset({device.request_id}),
                ),
            )
        self.assertEqual(auth.decisions[0].decision, Decision.DENY)
        self.assertIn("finite", auth.decisions[0].reason)

    def test_nonfinite_resource_target_is_hard_denied(self) -> None:
        resource = request(
            "ignored",
            CapabilityCategory.RESOURCE,
            "cpu",
            "nan",
            RiskLevel.LOW,
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                plan_for(resource),
                PolicyConfig(SAFE, Path(directory) / "output"),
            )
        self.assertEqual(auth.decisions[0].decision, Decision.DENY)
        self.assertIn("finite", auth.decisions[0].reason)

    def test_nonfinite_or_boolean_policy_ceiling_denies_every_request(self) -> None:
        process = request(
            "ignored",
            CapabilityCategory.PROCESS,
            "execute",
            "python",
            RiskLevel.LOW,
        )
        for override in (
            {"max_cpus": float("inf")},
            {"max_output_files": True},
        ):
            with self.subTest(override=override), tempfile.TemporaryDirectory() as directory:
                auth = PolicyEngine().authorize(
                    plan_for(process),
                    PolicyConfig(
                        SAFE,
                        Path(directory) / "output",
                        **override,
                    ),
                )
            self.assertEqual(auth.decisions[0].decision, Decision.DENY)
            self.assertIn("Policy ceiling", auth.decisions[0].reason)

    def test_secret_is_hard_denied_even_when_approved(self) -> None:
        secret = request("cap-secret00001", CapabilityCategory.SECRET, "read", "env:AWS_SECRET_ACCESS_KEY")
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                plan_for(secret),
                PolicyConfig(SAFE, Path(directory) / "output", frozenset({secret.request_id})),
            )
        self.assertEqual(auth.decisions[0].decision, Decision.DENY)

    def test_denied_observation_still_builds_restrictive_shadow_spec(self) -> None:
        secret = request("cap-secret00002", CapabilityCategory.SECRET, "read", "env:CANARY")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            plan = runtime_plan_for(secret)
            auth = PolicyEngine().authorize(plan, PolicyConfig(SAFE, output))
            spec = SandboxBuilder().build(SAFE, output, plan.steps[0], auth)
        self.assertEqual(spec.environment, ())
        self.assertEqual(spec.network_targets, ())

    def test_domain_allowlist_fails_closed_without_enforcing_proxy(self) -> None:
        network = request(
            "cap-network0001",
            CapabilityCategory.NETWORK,
            "download",
            "datasets.example.org",
            RiskLevel.MEDIUM,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            plan = runtime_plan_for(network)
            auth = PolicyEngine().authorize(
                plan,
                PolicyConfig(SAFE, output, network_allowlist=frozenset({network.target})),
            )
            self.assertEqual(auth.decisions[0].decision, Decision.ALLOW)
            spec = SandboxBuilder().build(SAFE, output, plan.steps[0], auth)
            result = DryRunExecutionSupervisor().execute(spec)
        self.assertEqual(result.status.value, "blocked")
        self.assertIn("egress proxy", result.stderr)

    def test_unknown_network_action_is_hard_denied(self) -> None:
        network = request(
            "ignored",
            CapabilityCategory.NETWORK,
            "exfiltrate_v2",
            "datasets.example.org",
            RiskLevel.MEDIUM,
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                plan_for(network),
                PolicyConfig(
                    SAFE,
                    Path(directory) / "output",
                    approved_request_ids=frozenset({network.request_id}),
                    network_allowlist=frozenset({network.target}),
                ),
            )
        self.assertEqual(auth.decisions[0].decision, Decision.DENY)

    def test_unknown_gpu_action_is_hard_denied(self) -> None:
        device = request(
            "ignored",
            CapabilityCategory.DEVICE,
            "raw_access",
            "gpu",
            RiskLevel.MEDIUM,
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                plan_for(device),
                PolicyConfig(
                    SAFE,
                    Path(directory) / "output",
                    approved_request_ids=frozenset({device.request_id}),
                ),
            )
        self.assertEqual(auth.decisions[0].decision, Decision.DENY)

    def test_gpu_inspection_is_denied_because_runtime_grants_full_access(self) -> None:
        device = request(
            "ignored",
            CapabilityCategory.DEVICE,
            "inspect",
            "gpu",
            RiskLevel.MEDIUM,
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                plan_for(device),
                PolicyConfig(
                    SAFE,
                    Path(directory) / "output",
                    approved_request_ids=frozenset({device.request_id}),
                ),
            )
        self.assertEqual(auth.decisions[0].decision, Decision.DENY)
        self.assertIn("full device access", auth.decisions[0].reason)

    def test_spawn_and_path_aliased_python_are_hard_denied(self) -> None:
        attempts = (
            request(
                "ignored",
                CapabilityCategory.PROCESS,
                "spawn",
                "python",
                RiskLevel.LOW,
            ),
            request(
                "ignored",
                CapabilityCategory.PROCESS,
                "execute",
                "/tmp/python",
                RiskLevel.LOW,
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            for attempt in attempts:
                with self.subTest(attempt=attempt):
                    auth = PolicyEngine().authorize(
                        plan_for(attempt),
                        PolicyConfig(SAFE, Path(directory) / "output"),
                    )
                    self.assertEqual(auth.decisions[0].decision, Decision.DENY)

    def test_dry_run_is_non_root_and_hardened(self) -> None:
        filesystem = request(
            "cap-filesystem2",
            CapabilityCategory.FILESYSTEM,
            "write",
            "<output>",
            RiskLevel.LOW,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            plan = runtime_plan_for(filesystem)
            auth = PolicyEngine().authorize(plan, PolicyConfig(SAFE, output))
            spec = SandboxBuilder().build(SAFE, output, plan.steps[0], auth)
            command = DryRunExecutionSupervisor().execute(spec).command_preview
        self.assertIn("--user", command)
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("--read-only", command)
        self.assertIn("ALL", command)
        self.assertIn("PYTHONPATH=/opt/r-sandbox-audit", command)
        self.assertIn("PYTHONSAFEPATH=1", command)
        entrypoint_index = command.index("--entrypoint")
        self.assertEqual(command[entrypoint_index + 1], "python")
        image_index = command.index(spec.image)
        self.assertGreater(image_index, entrypoint_index)
        self.assertEqual(command[image_index + 1], "-P")
        self.assertEqual(command[image_index + 2], "train.py")

    def test_image_option_injection_is_rejected(self) -> None:
        process = request(
            "ignored",
            CapabilityCategory.PROCESS,
            "execute",
            "python",
            RiskLevel.LOW,
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            plan = runtime_plan_for(process)
            auth = PolicyEngine().authorize(plan, PolicyConfig(SAFE, output))
            spec = SandboxBuilder().build(
                SAFE,
                output,
                plan.steps[0],
                auth,
            )
            result = DryRunExecutionSupervisor().execute(
                replace(spec, image="--privileged")
            )
        self.assertEqual(result.status, AgentOutcome.BLOCKED)
        self.assertIn("image reference", result.stderr)

    def test_output_must_be_disjoint_from_repository(self) -> None:
        filesystem = request(
            "cap-filesystem1",
            CapabilityCategory.FILESYSTEM,
            "write",
            "<output>",
            RiskLevel.LOW,
        )
        plan = runtime_plan_for(filesystem)
        output = SAFE / f".r-sandbox-disjoint-{uuid4().hex}"
        auth = PolicyEngine().authorize(plan, PolicyConfig(SAFE, output))
        with self.assertRaises(SandboxBuildError):
            SandboxBuilder().build(SAFE, output, plan.steps[0], auth)
        self.assertFalse(output.exists())

    def test_capability_id_cannot_be_reused_for_mutated_payload(self) -> None:
        original = request(
            "ignored",
            CapabilityCategory.NETWORK,
            "download",
            "datasets.example.org",
            RiskLevel.MEDIUM,
        )
        mutated = replace(original, target="collector.example.org")
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                plan_for(mutated),
                PolicyConfig(
                    SAFE,
                    Path(directory) / "output",
                    approved_request_ids=frozenset({original.request_id}),
                    network_allowlist=frozenset({mutated.target}),
                ),
            )
        self.assertEqual(auth.decisions[0].decision, Decision.DENY)
        self.assertIn("not bound", auth.decisions[0].reason)

    def test_malformed_network_target_is_hard_denied(self) -> None:
        malformed = request(
            "ignored",
            CapabilityCategory.NETWORK,
            "download",
            "http://[",
            RiskLevel.MEDIUM,
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                plan_for(malformed),
                PolicyConfig(SAFE, Path(directory) / "output"),
            )
        self.assertEqual(auth.decisions[0].decision, Decision.DENY)

    def test_arbitrary_device_is_hard_denied_even_with_approval(self) -> None:
        device = request(
            "cap-device00001",
            CapabilityCategory.DEVICE,
            "access",
            "/dev/sda",
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                plan_for(device),
                PolicyConfig(
                    SAFE,
                    Path(directory) / "output",
                    approved_request_ids=frozenset({device.request_id}),
                ),
            )
        self.assertEqual(auth.decisions[0].decision, Decision.DENY)

    def test_relative_output_alias_is_not_falsely_authorized(self) -> None:
        filesystem = request(
            "cap-filesystem3",
            CapabilityCategory.FILESYSTEM,
            "write",
            "outputs/model.bin",
            RiskLevel.MEDIUM,
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                plan_for(filesystem),
                PolicyConfig(SAFE, Path(directory) / "output"),
            )
        self.assertEqual(auth.decisions[0].decision, Decision.DENY)

    def test_builder_binds_argv_to_process_authorization(self) -> None:
        process = request(
            "cap-process0001",
            CapabilityCategory.PROCESS,
            "execute",
            "python",
            RiskLevel.LOW,
        )
        malicious_plan = ExecutionPlan(
            "test",
            "test",
            (
                PlanStep(
                    "step",
                    "test",
                    ("sh", "-c", "id"),
                    capabilities=(process,),
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                malicious_plan,
                PolicyConfig(SAFE, Path(directory) / "output"),
            )
            with self.assertRaises(SandboxBuildError):
                SandboxBuilder().build(
                    SAFE,
                    Path(directory) / "output",
                    malicious_plan.steps[0],
                    auth,
                )

    def test_builder_rejects_implicit_mounts_without_allow_capabilities(self) -> None:
        process = request(
            "ignored",
            CapabilityCategory.PROCESS,
            "execute",
            "python",
            RiskLevel.LOW,
        )
        plan = plan_for(process)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            auth = PolicyEngine().authorize(plan, PolicyConfig(SAFE, output))
            with self.assertRaises(UnauthorizedCapabilityError) as raised:
                SandboxBuilder().build(SAFE, output, plan.steps[0], auth)
        self.assertIn("repository mount", str(raised.exception))

    def test_builder_rejects_resource_limit_above_allowed_grant(self) -> None:
        plan = runtime_plan_for()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            auth = PolicyEngine().authorize(plan, PolicyConfig(SAFE, output))
            with self.assertRaises(UnauthorizedCapabilityError) as raised:
                SandboxBuilder().build(
                    SAFE,
                    output,
                    plan.steps[0],
                    auth,
                    limits=ResourceLimits(cpus=2.0),
                )
        self.assertIn("cpu=2", str(raised.exception))

    def test_builder_rejects_output_limit_above_allowed_grant(self) -> None:
        plan = runtime_plan_for()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            auth = PolicyEngine().authorize(plan, PolicyConfig(SAFE, output))
            with self.assertRaises(UnauthorizedCapabilityError) as raised:
                SandboxBuilder().build(
                    SAFE,
                    output,
                    plan.steps[0],
                    auth,
                    limits=ResourceLimits(output_files=10_001),
                )
        self.assertIn("output_files=10001", str(raised.exception))

    def test_resource_model_rejects_nan_cpu_limit(self) -> None:
        with self.assertRaisesRegex(TypeError, "cpus"):
            ResourceLimits(cpus=float("nan"))

    def test_builder_normalizes_mutated_huge_cpu_limit_to_build_error(self) -> None:
        plan = runtime_plan_for()
        limits = ResourceLimits()
        object.__setattr__(limits, "cpus", 10**1000)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            authorization = PolicyEngine().authorize(plan, PolicyConfig(SAFE, output))
            with self.assertRaisesRegex(SandboxBuildError, "CPU limit"):
                SandboxBuilder().build(
                    SAFE,
                    output,
                    plan.steps[0],
                    authorization,
                    limits=limits,
                )

    def test_builder_rejects_python_inline_code(self) -> None:
        process = request(
            "cap-process0002",
            CapabilityCategory.PROCESS,
            "execute",
            "python",
            RiskLevel.LOW,
        )
        inline_plan = ExecutionPlan(
            "test",
            "test",
            (
                PlanStep(
                    "step",
                    "test",
                    ("python", "-c", "print('bypass')"),
                    capabilities=(process,),
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            auth = PolicyEngine().authorize(
                inline_plan,
                PolicyConfig(SAFE, Path(directory) / "output"),
            )
            with self.assertRaises(SandboxBuildError):
                SandboxBuilder().build(
                    SAFE,
                    Path(directory) / "output",
                    inline_plan.steps[0],
                    auth,
                )


if __name__ == "__main__":
    unittest.main()
