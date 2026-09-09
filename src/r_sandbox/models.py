"""Shared, serializable contracts for the R-Sandbox agent and its tools.

The LLM-facing parts of the system may propose these objects, but only the
deterministic policy and runtime layers are allowed to turn them into host
effects.  Keeping the boundary explicit is a core security property.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
import math
from pathlib import Path
from typing import Any


class AgentPhase(StrEnum):
    OBSERVE = "observe"
    UNDERSTAND = "understand"
    PLAN = "plan"
    AUTHORIZE = "authorize"
    BUILD = "build"
    EXECUTE = "execute"
    MONITOR = "monitor"
    REFLECT = "reflect"
    REPLAN = "replan"
    REPORT = "report"


class CapabilityCategory(StrEnum):
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    PROCESS = "process"
    SECRET = "secret"
    DEVICE = "device"
    RESOURCE = "resource"
    SIDE_EFFECT = "side_effect"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class AgentOutcome(StrEnum):
    ANALYZED = "analyzed"
    PLANNED = "planned"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNTIME_UNAVAILABLE = "runtime_unavailable"


class SecurityVerdict(StrEnum):
    SAFE = "safe"
    REVIEW = "review"
    UNSAFE = "unsafe"
    INCONCLUSIVE = "inconclusive"


class RuntimeEvidenceSource(StrEnum):
    TARGET_TELEMETRY = "target_telemetry"
    SUPERVISOR = "supervisor"
    INDEPENDENT_OBSERVER = "independent_observer"


class EnvironmentReadiness(StrEnum):
    NO_DECLARED_DEPENDENCIES = "no_declared_dependencies"
    PREBUILT_IMAGE_REQUIRED = "prebuilt_image_required"


@dataclass(frozen=True, slots=True)
class Evidence:
    source: str
    detail: str
    line: int | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    category: CapabilityCategory
    action: str
    target: str
    risk: RiskLevel
    reason: str
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class Dependency:
    name: str
    specifier: str = ""
    source: str = ""


@dataclass(frozen=True, slots=True)
class Entrypoint:
    path: str
    argv: tuple[str, ...]
    confidence: float
    evidence: str


@dataclass(frozen=True, slots=True)
class RepositoryProfile:
    root: str
    goal: str
    summary: str
    files: tuple[str, ...]
    entrypoints: tuple[Entrypoint, ...]
    dependencies: tuple[Dependency, ...]
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...] = ()
    snapshot_digest: str = ""
    snapshot_omissions: tuple[str, ...] = ()
    authorization_context: str = ""


@dataclass(frozen=True, slots=True)
class EnvironmentPlan:
    runtime: str
    image: str
    image_pinned: bool
    readiness: EnvironmentReadiness
    dependencies: tuple[Dependency, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CapabilityRequest:
    request_id: str
    category: CapabilityCategory
    action: str
    target: str
    justification: str
    confidence: float
    risk: RiskLevel
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class PlanStep:
    step_id: str
    purpose: str
    argv: tuple[str, ...]
    cwd: str = "/workspace"
    capabilities: tuple[CapabilityRequest, ...] = ()


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    goal: str
    summary: str
    steps: tuple[PlanStep, ...]
    assumptions: tuple[str, ...] = ()
    attempt: int = 1


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    request: CapabilityRequest
    decision: Decision
    reason: str


@dataclass(frozen=True, slots=True)
class Authorization:
    decisions: tuple[PolicyDecision, ...]

    @property
    def pending(self) -> tuple[PolicyDecision, ...]:
        return tuple(d for d in self.decisions if d.decision == Decision.REQUIRE_APPROVAL)

    @property
    def denied(self) -> tuple[PolicyDecision, ...]:
        return tuple(d for d in self.decisions if d.decision == Decision.DENY)

    @property
    def allowed(self) -> tuple[PolicyDecision, ...]:
        return tuple(d for d in self.decisions if d.decision == Decision.ALLOW)


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    cpus: float = 1.0
    memory_mb: int = 1024
    pids: int = 128
    timeout_seconds: int = 300
    output_mb: int = 1024
    output_files: int = 10_000
    temporary_mb: int = 64
    shared_memory_mb: int = 16

    def __post_init__(self) -> None:
        try:
            valid_cpus = (
                type(self.cpus) in {int, float}
                and math.isfinite(float(self.cpus))
                and 0 < float(self.cpus) <= 32
            )
        except (OverflowError, TypeError, ValueError):
            valid_cpus = False
        if not valid_cpus:
            raise TypeError("cpus must be an exact finite number in (0, 32]")
        integer_bounds = (
            ("memory_mb", self.memory_mb, 65_536),
            ("pids", self.pids, 4_096),
            ("timeout_seconds", self.timeout_seconds, 86_400),
            ("output_mb", self.output_mb, 65_536),
            ("output_files", self.output_files, 1_000_000),
            ("temporary_mb", self.temporary_mb, 16_384),
            ("shared_memory_mb", self.shared_memory_mb, 16_384),
        )
        for name, value, maximum in integer_bounds:
            if type(value) is not int or not 0 < value <= maximum:
                raise TypeError(
                    f"{name} must be an exact positive integer no greater than {maximum}"
                )


@dataclass(frozen=True, slots=True)
class SandboxSpec:
    repository: str
    output: str
    image: str
    argv: tuple[str, ...]
    source_repository: str = ""
    snapshot_digest: str = ""
    network_targets: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    devices: tuple[str, ...] = ()
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    read_only_root: bool = True
    drop_capabilities: bool = True

    def __post_init__(self) -> None:
        for name, value, allow_empty in (
            ("repository", self.repository, False),
            ("output", self.output, False),
            ("image", self.image, False),
            ("source_repository", self.source_repository, True),
            ("snapshot_digest", self.snapshot_digest, True),
        ):
            if type(value) is not str:
                raise TypeError(f"sandbox {name} must be an exact string")
            if (not allow_empty and not value) or "\x00" in value or len(value) > 32_768:
                raise ValueError(f"sandbox {name} is not bounded text")
        for name, values, maximum in (
            ("argv", self.argv, 256),
            ("network_targets", self.network_targets, 256),
            ("devices", self.devices, 16),
        ):
            if type(values) is not tuple or not (
                1 <= len(values) <= maximum if name == "argv" else len(values) <= maximum
            ):
                raise TypeError(f"sandbox {name} must be a bounded exact tuple")
            if any(
                type(item) is not str
                or not item
                or len(item) > 8_192
                or "\x00" in item
                for item in values
            ):
                raise TypeError(f"sandbox {name} must contain exact bounded strings")
        if type(self.environment) is not tuple or len(self.environment) > 256:
            raise TypeError("sandbox environment must be a bounded exact tuple")
        for item in self.environment:
            if (
                type(item) is not tuple
                or len(item) != 2
                or any(
                    type(part) is not str
                    or not part
                    or len(part) > 8_192
                    or "\x00" in part
                    for part in item
                )
            ):
                raise TypeError(
                    "sandbox environment entries must be exact string pairs"
                )
        if type(self.limits) is not ResourceLimits:
            raise TypeError("sandbox limits must be an exact ResourceLimits value")
        if type(self.read_only_root) is not bool or type(self.drop_capabilities) is not bool:
            raise TypeError("sandbox hardening flags must be exact booleans")


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    event_type: str
    action: str
    target: str
    allowed: bool
    detail: str = ""
    source: RuntimeEvidenceSource = RuntimeEvidenceSource.TARGET_TELEMETRY

    def __post_init__(self) -> None:
        for name, value, maximum, allow_empty in (
            ("event_type", self.event_type, 128, False),
            ("action", self.action, 128, False),
            ("target", self.target, 8_192, False),
            ("detail", self.detail, 16_384, True),
        ):
            if type(value) is not str:
                raise TypeError(f"runtime event {name} must be a string")
            if not allow_empty and not value:
                raise ValueError(f"runtime event {name} must not be empty")
            if len(value) > maximum or "\x00" in value:
                raise ValueError(f"runtime event {name} is not bounded text")
        if type(self.allowed) is not bool:
            raise TypeError("runtime event allowed must be a boolean")
        if type(self.source) is not RuntimeEvidenceSource:
            raise TypeError("runtime event source must be a RuntimeEvidenceSource")


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    status: AgentOutcome
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    events: tuple[RuntimeEvent, ...] = ()
    command_preview: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.status) is not AgentOutcome:
            raise TypeError("execution status must be an AgentOutcome")
        if self.exit_code is not None and (
            type(self.exit_code) is not int
            or not -(2**31) <= self.exit_code < 2**31
        ):
            raise TypeError("execution exit_code must be a bounded integer or null")
        if self.status == AgentOutcome.SUCCEEDED and self.exit_code != 0:
            raise ValueError("a succeeded execution must have exit_code 0")
        if self.status == AgentOutcome.FAILED and self.exit_code == 0:
            raise ValueError("a failed execution cannot have exit_code 0")
        if self.status in {
            AgentOutcome.ANALYZED,
            AgentOutcome.PLANNED,
            AgentOutcome.BLOCKED,
            AgentOutcome.AWAITING_APPROVAL,
            AgentOutcome.RUNTIME_UNAVAILABLE,
        } and self.exit_code is not None:
            raise ValueError(
                f"{self.status.value} execution must not carry a process exit code"
            )
        try:
            valid_duration = (
                type(self.duration_seconds) in {int, float}
                and math.isfinite(float(self.duration_seconds))
                and self.duration_seconds >= 0
            )
        except (OverflowError, TypeError, ValueError):
            valid_duration = False
        if not valid_duration:
            raise TypeError("execution duration must be a finite non-negative number")
        for name, value in (("stdout", self.stdout), ("stderr", self.stderr)):
            if type(value) is not str:
                raise TypeError(f"execution {name} must be a string")
            if len(value) > 1_100_000:
                raise ValueError(f"execution {name} exceeds the report boundary")
        if type(self.events) is not tuple or len(self.events) > 10_100:
            raise TypeError("execution events must be a bounded tuple")
        if any(type(item) is not RuntimeEvent for item in self.events):
            raise TypeError("execution events must contain only RuntimeEvent values")
        if type(self.command_preview) is not tuple or len(self.command_preview) > 1_024:
            raise TypeError("execution command_preview must be a bounded tuple")
        if any(
            type(item) is not str or not item or len(item) > 8_192 or "\x00" in item
            for item in self.command_preview
        ):
            raise TypeError("execution command_preview must contain bounded argv strings")


def canonical_execution_result(result: ExecutionResult) -> ExecutionResult:
    """Take an exact, immutable snapshot at a supervisor trust boundary.

    Execution supervisors are replaceable adapters.  Their return value must
    therefore be treated like parsed input rather than as an already trusted
    dataclass; subclasses and post-construction mutation must not reach the
    observer or security assessor.
    """

    if type(result) is not ExecutionResult:
        raise TypeError("execution result must use the exact ExecutionResult type")
    if type(result.events) is not tuple or any(
        type(event) is not RuntimeEvent for event in result.events
    ):
        raise TypeError("execution result contains a non-exact runtime event")
    events = tuple(
        RuntimeEvent(
            event_type=event.event_type,
            action=event.action,
            target=event.target,
            allowed=event.allowed,
            detail=event.detail,
            source=event.source,
        )
        for event in result.events
    )
    return ExecutionResult(
        status=result.status,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        duration_seconds=result.duration_seconds,
        events=events,
        command_preview=result.command_preview,
    )


@dataclass(frozen=True, slots=True)
class Reflection:
    classification: str
    explanation: str
    should_retry: bool = False
    proposed_capabilities: tuple[CapabilityRequest, ...] = ()
    plan_changes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PhaseRecord:
    phase: AgentPhase
    message: str


@dataclass(frozen=True, slots=True)
class SecurityAssessment:
    """Evidence-backed judgement produced after static and shadow analysis."""

    verdict: SecurityVerdict
    risk_score: int
    summary: str
    reasons: tuple[str, ...] = ()
    static_findings: tuple[Finding, ...] = ()
    runtime_events: tuple[RuntimeEvent, ...] = ()


@dataclass(slots=True)
class AgentReport:
    outcome: AgentOutcome
    goal: str
    repository: str
    profile: RepositoryProfile | None = None
    environment_plan: EnvironmentPlan | None = None
    plan: ExecutionPlan | None = None
    authorization: Authorization | None = None
    sandbox: SandboxSpec | None = None
    execution: ExecutionResult | None = None
    execution_history: list[ExecutionResult] = field(default_factory=list)
    security_assessment: SecurityAssessment | None = None
    reflections: list[Reflection] = field(default_factory=list)
    timeline: list[PhaseRecord] = field(default_factory=list)
    files_changed: list[str] = field(default_factory=list)
    reproduction: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        snapshot = canonical_agent_report(self)
        payload = _json_value(asdict(snapshot))
        if snapshot.execution is not None:
            _sanitize_execution_payload(
                snapshot.execution,
                payload["execution"],
            )
        for result, result_payload in zip(
            snapshot.execution_history,
            payload["execution_history"],
            strict=True,
        ):
            _sanitize_execution_payload(result, result_payload)
        if snapshot.security_assessment is not None:
            _redact_target_event_payloads(
                snapshot.security_assessment.runtime_events,
                payload["security_assessment"]["runtime_events"],
            )
        payload["files_changed"] = [
            {"path": "<target-controlled-artifact-path-omitted>"}
            for _item in self.files_changed
        ]
        if snapshot.security_assessment is None:
            gate_result = "not_evaluated"
        elif snapshot.security_assessment.verdict == SecurityVerdict.SAFE:
            gate_result = "pass"
        elif snapshot.security_assessment.verdict == SecurityVerdict.INCONCLUSIVE:
            gate_result = "inconclusive"
        else:
            gate_result = "fail"
        payload["security_gate_result"] = gate_result
        return payload


def canonical_findings(findings: object) -> tuple[Finding, ...]:
    """Detach exact static findings before they affect a security verdict."""

    if type(findings) is not tuple or len(findings) > 100_000:
        raise TypeError("security findings must be a bounded exact tuple")
    canonical: list[Finding] = []
    for finding in findings:
        if type(finding) is not Finding:
            raise TypeError("security findings must contain exact Finding values")
        if type(finding.category) is not CapabilityCategory:
            raise TypeError("finding category must be a CapabilityCategory")
        if type(finding.risk) is not RiskLevel:
            raise TypeError("finding risk must be a RiskLevel")
        for value in (
            finding.finding_id,
            finding.action,
            finding.target,
            finding.reason,
        ):
            if type(value) is not str or not value or len(value) > 32_768 or "\x00" in value:
                raise TypeError("finding text fields must be exact bounded strings")
        if type(finding.evidence) is not tuple or len(finding.evidence) > 1_024:
            raise TypeError("finding evidence must be a bounded exact tuple")
        evidence_items: list[Evidence] = []
        for evidence in finding.evidence:
            if type(evidence) is not Evidence:
                raise TypeError("finding evidence must contain exact Evidence values")
            if (
                type(evidence.source) is not str
                or type(evidence.detail) is not str
                or len(evidence.source) > 8_192
                or len(evidence.detail) > 32_768
                or "\x00" in evidence.source
                or "\x00" in evidence.detail
                or (
                    evidence.line is not None
                    and (type(evidence.line) is not int or not 1 <= evidence.line <= 2_147_483_647)
                )
            ):
                raise TypeError("finding evidence contains malformed fields")
            evidence_items.append(
                Evidence(evidence.source, evidence.detail, evidence.line)
            )
        canonical.append(
            Finding(
                finding_id=finding.finding_id,
                category=finding.category,
                action=finding.action,
                target=finding.target,
                risk=finding.risk,
                reason=finding.reason,
                evidence=tuple(evidence_items),
            )
        )
    return tuple(canonical)


def canonical_security_assessment(value: object) -> SecurityAssessment:
    """Snapshot an assessment before it controls a serialized gate result."""

    if type(value) is not SecurityAssessment:
        raise TypeError("security assessment must use the exact SecurityAssessment type")
    if type(value.verdict) is not SecurityVerdict:
        raise TypeError("security assessment verdict must be a SecurityVerdict")
    if type(value.risk_score) is not int or not 0 <= value.risk_score <= 100:
        raise TypeError("security assessment risk_score must be an integer in 0..100")
    if type(value.summary) is not str or not value.summary or len(value.summary) > 32_768:
        raise TypeError("security assessment summary must be exact bounded text")
    if type(value.reasons) is not tuple or len(value.reasons) > 10_000 or any(
        type(reason) is not str or len(reason) > 32_768 or "\x00" in reason
        for reason in value.reasons
    ):
        raise TypeError("security assessment reasons must be bounded exact text")
    findings = canonical_findings(value.static_findings)
    if type(value.runtime_events) is not tuple or len(value.runtime_events) > 10_100:
        raise TypeError("assessment runtime events must be a bounded exact tuple")
    events = tuple(
        RuntimeEvent(
            event_type=event.event_type,
            action=event.action,
            target=event.target,
            allowed=event.allowed,
            detail=event.detail,
            source=event.source,
        )
        for event in value.runtime_events
        if type(event) is RuntimeEvent
    )
    if len(events) != len(value.runtime_events):
        raise TypeError("assessment runtime events must contain exact RuntimeEvent values")
    return SecurityAssessment(
        verdict=value.verdict,
        risk_score=value.risk_score,
        summary=value.summary,
        reasons=tuple(value.reasons),
        static_findings=findings,
        runtime_events=events,
    )


def canonical_agent_report(report: object) -> AgentReport:
    """Snapshot security-bearing report fields and enforce cross-field invariants."""

    if type(report) is not AgentReport:
        raise TypeError("report must use the exact AgentReport type")
    if type(report.outcome) is not AgentOutcome:
        raise TypeError("report outcome must be an AgentOutcome")
    for name, value in (("goal", report.goal), ("repository", report.repository)):
        if type(value) is not str or not value or len(value) > 32_768 or "\x00" in value:
            raise TypeError(f"report {name} must be exact bounded text")
    execution = (
        None
        if report.execution is None
        else canonical_execution_result(report.execution)
    )
    if type(report.execution_history) is not list or len(report.execution_history) > 1_000:
        raise TypeError("report execution_history must be a bounded exact list")
    history = [canonical_execution_result(item) for item in report.execution_history]
    assessment = (
        None
        if report.security_assessment is None
        else canonical_security_assessment(report.security_assessment)
    )
    if assessment is not None and assessment.verdict == SecurityVerdict.SAFE:
        # The bundled contract has no typed, run-bound independent coverage
        # attestation, so accepting a caller-constructed SAFE would fabricate a
        # guarantee the current system cannot establish.
        raise ValueError("SAFE reports require an unavailable typed coverage attestation")
    if execution is None:
        if history:
            raise ValueError(
                "report execution_history must be empty when execution is absent"
            )
        if report.outcome in {
            AgentOutcome.SUCCEEDED,
            AgentOutcome.FAILED,
            AgentOutcome.RUNTIME_UNAVAILABLE,
        }:
            raise ValueError(
                "terminal process outcomes require a final execution result"
            )
    else:
        if not history:
            raise ValueError(
                "report execution requires a non-empty execution_history"
            )
        if history[-1] != execution:
            raise ValueError(
                "report execution must equal the final execution_history result"
            )
        if report.outcome != execution.status:
            raise ValueError(
                "report outcome must match the final execution status"
            )
    for name in ("reflections", "timeline", "files_changed", "reproduction", "notes"):
        if type(getattr(report, name)) is not list:
            raise TypeError(f"report {name} must be an exact list")
    return AgentReport(
        outcome=report.outcome,
        goal=report.goal,
        repository=report.repository,
        profile=report.profile,
        environment_plan=report.environment_plan,
        plan=report.plan,
        authorization=report.authorization,
        sandbox=report.sandbox,
        execution=execution,
        execution_history=history,
        security_assessment=assessment,
        reflections=list(report.reflections),
        timeline=list(report.timeline),
        files_changed=list(report.files_changed),
        reproduction=list(report.reproduction),
        notes=list(report.notes),
    )


def _stream_summary(value: str) -> dict[str, Any]:
    encoded = value.encode("utf-8", errors="replace")
    return {
        "characters": len(value),
        "bytes": len(encoded),
        "present": bool(value),
    }


def _sanitize_execution_payload(
    result: ExecutionResult,
    payload: dict[str, Any],
) -> None:
    payload["stdout"] = None
    payload["stderr"] = None
    payload["stream_summary"] = {
        "stdout": _stream_summary(result.stdout),
        "stderr": _stream_summary(result.stderr),
        "raw_content": "omitted_from_report",
    }
    _redact_target_event_payloads(result.events, payload["events"])


_TARGET_EVENT_TYPES = frozenset(
    {"filesystem", "network", "process", "secret", "device", "runtime"}
)
_TARGET_EVENT_ACTIONS = frozenset(
    {
        "read",
        "write",
        "mutate",
        "rename",
        "spawn",
        "connect",
        "connect_unknown",
        "download",
        "send",
        "audit_hook",
    }
)


def _redact_target_event_payloads(
    events: tuple[RuntimeEvent, ...],
    payloads: list[dict[str, Any]],
) -> None:
    for event, payload in zip(events, payloads, strict=True):
        if event.source != RuntimeEvidenceSource.TARGET_TELEMETRY:
            continue
        payload["event_type"] = (
            event.event_type
            if event.event_type in _TARGET_EVENT_TYPES
            else "unrecognized_target_event"
        )
        payload["action"] = (
            event.action
            if event.action in _TARGET_EVENT_ACTIONS
            else "unrecognized_target_action"
        )
        payload["target"] = "<target-controlled-content-omitted>"
        payload["detail"] = "Target-controlled content omitted from report."


def _json_value(value: Any) -> Any:
    if isinstance(value, Path):
        return _utf8_safe_report_text(str(value))
    if isinstance(value, StrEnum):
        return _utf8_safe_report_text(value.value)
    if isinstance(value, str):
        return _utf8_safe_report_text(value)
    if isinstance(value, dict):
        return {
            _utf8_safe_report_text(str(key)): _json_value(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _utf8_safe_report_text(value: str) -> str:
    """Escape lone surrogates while preserving normal Unicode report text."""

    return "".join(
        f"\\u{ord(character):04x}"
        if 0xD800 <= ord(character) <= 0xDFFF
        else character
        for character in value
    )
