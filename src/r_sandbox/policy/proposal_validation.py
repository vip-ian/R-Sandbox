"""Strict runtime validation for semantic-layer execution proposals.

Dataclass annotations are not a security boundary: Python callers can still
construct instances containing values of the wrong type.  This module checks
the complete proposal before policy normalization, identity calculation, or
capability evaluation occurs.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import math
import re
from urllib.parse import urlparse

from r_sandbox.models import (
    Authorization,
    CapabilityCategory,
    CapabilityRequest,
    Decision,
    Evidence,
    ExecutionPlan,
    PlanStep,
    PolicyDecision,
    RiskLevel,
)


MAX_PLAN_STEPS = 1
MAX_CAPABILITIES_PER_STEP = 6_000
MAX_CAPABILITIES_PER_PLAN = 6_000
MAX_ASSUMPTIONS = 256
MAX_ARGV_ITEMS = 256
MAX_EVIDENCE_ITEMS = 128

_REQUEST_ID_RE = re.compile(r"^cap-[0-9a-f]{32}$")
_MAX_GOAL_LENGTH = 16_384
_MAX_SUMMARY_LENGTH = 32_768
_MAX_STEP_ID_LENGTH = 256
_MAX_PURPOSE_LENGTH = 16_384
_MAX_CWD_LENGTH = 4_096
_MAX_ARG_LENGTH = 8_192
_MAX_ASSUMPTION_LENGTH = 16_384
_MAX_ACTION_LENGTH = 128
_MAX_TARGET_LENGTH = 8_192
_MAX_JUSTIFICATION_LENGTH = 16_384
_MAX_EVIDENCE_SOURCE_LENGTH = 4_096
_MAX_EVIDENCE_DETAIL_LENGTH = 16_384
_MAX_LINE_NUMBER = 2_147_483_647
_MAX_ATTEMPT = 1_000
_MAX_POLICY_REASON_LENGTH = 32_768


@dataclass(frozen=True, slots=True)
class ValidatedRequest:
    """One structurally safe request and any value-level validation error."""

    request: CapabilityRequest
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ValidatedPlan:
    """An exact immutable snapshot of one untrusted semantic proposal."""

    plan: ExecutionPlan
    requests: tuple[ValidatedRequest, ...]


def quarantine_request(
    request: CapabilityRequest,
    error: str,
    index: int,
) -> CapabilityRequest:
    """Return a canonical safe placeholder for a rejected request.

    The original proposal remains untrusted and must not be handed to policy
    consumers that assume the dataclass contract.  The placeholder retains
    only the already-validated category; no attacker-controlled field content
    is copied into the authorization result.
    """

    material = f"{index}:{request.category.value}:{error}".encode("utf-8")
    return CapabilityRequest(
        request_id="cap-" + sha256(material).hexdigest()[:32],
        category=request.category,
        action="invalid_proposal",
        target="<malformed-capability>",
        justification=f"Rejected at proposal validation boundary: {error}.",
        confidence=0.0,
        risk=RiskLevel.CRITICAL,
        evidence=(),
    )


def validate_execution_plan(plan: object) -> ValidatedPlan:
    """Validate a complete untrusted proposal without performing host I/O.

    Structural violations raise ``ValueError`` because they cannot safely be
    represented by the typed authorization result.  Value-level violations in
    an otherwise well-shaped ``CapabilityRequest`` are returned so the policy
    engine can record deterministic denials for the entire proposal.
    """

    if type(plan) is not ExecutionPlan:
        raise ValueError("Malformed execution plan: expected ExecutionPlan.")

    # Capture every field once and build fresh dataclasses. Frozen dataclasses
    # can still be changed with object.__setattr__, so policy must never retain
    # semantic-layer objects across the authorize/build boundary.
    goal = plan.goal
    summary = plan.summary
    steps = plan.steps
    assumptions = plan.assumptions
    attempt = plan.attempt
    _require_text(goal, "plan.goal", _MAX_GOAL_LENGTH)
    _require_text(summary, "plan.summary", _MAX_SUMMARY_LENGTH)
    if type(steps) is not tuple:
        raise ValueError("Malformed execution plan: plan.steps must be a tuple.")
    if len(steps) > MAX_PLAN_STEPS:
        raise ValueError(
            f"Malformed execution plan: at most {MAX_PLAN_STEPS} steps are allowed."
        )
    if type(assumptions) is not tuple:
        raise ValueError("Malformed execution plan: plan.assumptions must be a tuple.")
    if len(assumptions) > MAX_ASSUMPTIONS:
        raise ValueError(
            f"Malformed execution plan: at most {MAX_ASSUMPTIONS} assumptions are allowed."
        )
    for index, assumption in enumerate(assumptions):
        _require_text(
            assumption,
            f"plan.assumptions[{index}]",
            _MAX_ASSUMPTION_LENGTH,
        )
    if type(attempt) is not int or not 1 <= attempt <= _MAX_ATTEMPT:
        raise ValueError(
            f"Malformed execution plan: plan.attempt must be an integer from 1 to {_MAX_ATTEMPT}."
        )

    validated: list[ValidatedRequest] = []
    step_ids: set[str] = set()
    request_ids: set[str] = set()
    total_capabilities = 0
    canonical_steps: list[PlanStep] = []
    for step_index, step in enumerate(steps):
        if type(step) is not PlanStep:
            raise ValueError(
                f"Malformed execution plan: plan.steps[{step_index}] must be PlanStep."
            )
        step_id = step.step_id
        purpose = step.purpose
        argv = step.argv
        cwd = step.cwd
        capabilities = step.capabilities
        _require_text(step_id, f"plan.steps[{step_index}].step_id", _MAX_STEP_ID_LENGTH)
        if step_id in step_ids:
            raise ValueError("Malformed execution plan: step ids must be unique.")
        step_ids.add(step_id)
        _require_text(purpose, f"plan.steps[{step_index}].purpose", _MAX_PURPOSE_LENGTH)
        _require_text(cwd, f"plan.steps[{step_index}].cwd", _MAX_CWD_LENGTH)
        if type(argv) is not tuple:
            raise ValueError(
                f"Malformed execution plan: plan.steps[{step_index}].argv must be a tuple."
            )
        if not argv or len(argv) > MAX_ARGV_ITEMS:
            raise ValueError(
                "Malformed execution plan: each step argv must contain between "
                f"1 and {MAX_ARGV_ITEMS} items."
            )
        for arg_index, argument in enumerate(argv):
            _require_text(
                argument,
                f"plan.steps[{step_index}].argv[{arg_index}]",
                _MAX_ARG_LENGTH,
            )
        if type(capabilities) is not tuple:
            raise ValueError(
                f"Malformed execution plan: plan.steps[{step_index}].capabilities must be a tuple."
            )
        if len(capabilities) > MAX_CAPABILITIES_PER_STEP:
            raise ValueError(
                "Malformed execution plan: a step contains too many capability requests."
            )
        total_capabilities += len(capabilities)
        if total_capabilities > MAX_CAPABILITIES_PER_PLAN:
            raise ValueError(
                "Malformed execution plan: the plan contains too many capability requests."
            )
        canonical_requests: list[CapabilityRequest] = []
        for request_index, request in enumerate(capabilities):
            field = f"plan.steps[{step_index}].capabilities[{request_index}]"
            if type(request) is not CapabilityRequest:
                raise ValueError(f"Malformed execution plan: {field} must be CapabilityRequest.")
            canonical_request = _canonical_request(request, field)
            if canonical_request.request_id in request_ids:
                raise ValueError(
                    "Malformed execution plan: capability request ids must be unique."
                )
            request_ids.add(canonical_request.request_id)
            canonical_requests.append(canonical_request)
            validated.append(
                ValidatedRequest(
                    canonical_request,
                    _request_value_error(canonical_request)
                    or _category_value_error(canonical_request),
                )
            )
        canonical_steps.append(
            PlanStep(
                step_id=step_id,
                purpose=purpose,
                argv=tuple(argv),
                cwd=cwd,
                capabilities=tuple(canonical_requests),
            )
        )

    return ValidatedPlan(
        plan=ExecutionPlan(
            goal=goal,
            summary=summary,
            steps=tuple(canonical_steps),
            assumptions=tuple(assumptions),
            attempt=attempt,
        ),
        requests=tuple(validated),
    )


def _canonical_request(request: CapabilityRequest, field: str) -> CapabilityRequest:
    category = request.category
    risk = request.risk
    request_id = request.request_id
    action = request.action
    target = request.target
    justification = request.justification
    confidence = request.confidence
    evidence = request.evidence
    if type(category) is not CapabilityCategory:
        raise ValueError(f"Malformed execution plan: {field}.category has an invalid enum type.")
    if type(risk) is not RiskLevel:
        raise ValueError(f"Malformed execution plan: {field}.risk has an invalid enum type.")
    for name, value in (
        ("request_id", request_id),
        ("action", action),
        ("target", target),
        ("justification", justification),
    ):
        if type(value) is not str:
            raise ValueError(
                f"Malformed execution plan: {field}.{name} must be a string."
            )
    if type(confidence) not in {bool, int, float}:
        raise ValueError(
            f"Malformed execution plan: {field}.confidence must be a number."
        )
    if type(evidence) is not tuple:
        raise ValueError(f"Malformed execution plan: {field}.evidence must be a tuple.")
    if len(evidence) > MAX_EVIDENCE_ITEMS:
        raise ValueError(
            f"Malformed execution plan: {field}.evidence exceeds {MAX_EVIDENCE_ITEMS} items."
        )
    canonical_evidence: list[Evidence] = []
    for index, item in enumerate(evidence):
        if type(item) is not Evidence:
            raise ValueError(
                f"Malformed execution plan: {field}.evidence[{index}] must be Evidence."
            )
        source = item.source
        detail = item.detail
        line = item.line
        if type(source) is not str or type(detail) is not str:
            raise ValueError(
                f"Malformed execution plan: {field}.evidence[{index}] text fields must be strings."
            )
        if line is not None and type(line) not in {bool, int}:
            raise ValueError(
                f"Malformed execution plan: {field}.evidence[{index}].line must be an integer or null."
            )
        canonical_evidence.append(Evidence(source=source, detail=detail, line=line))
    return CapabilityRequest(
        request_id=request_id,
        category=category,
        action=action,
        target=target,
        justification=justification,
        confidence=confidence,
        risk=risk,
        evidence=tuple(canonical_evidence),
    )


def canonical_plan_step(step: object) -> PlanStep:
    """Validate and detach a step before it enters the runtime builder."""

    validated = validate_execution_plan(
        ExecutionPlan(
            goal="runtime-boundary",
            summary="canonical runtime step",
            steps=(step,),
        )
    )
    if any(item.error is not None for item in validated.requests):
        raise ValueError("Malformed execution plan: step has an invalid capability value.")
    return validated.plan.steps[0]


def canonical_authorization(authorization: object) -> Authorization:
    """Detach exact policy output before deriving any runtime grant."""

    if type(authorization) is not Authorization:
        raise ValueError("Malformed authorization: expected Authorization.")
    decisions = authorization.decisions
    if type(decisions) is not tuple or len(decisions) > MAX_CAPABILITIES_PER_PLAN:
        raise ValueError("Malformed authorization: decisions must be a bounded tuple.")
    canonical: list[PolicyDecision] = []
    for index, item in enumerate(decisions):
        if type(item) is not PolicyDecision:
            raise ValueError("Malformed authorization: decision must be PolicyDecision.")
        if type(item.decision) is not Decision:
            raise ValueError("Malformed authorization: decision enum is invalid.")
        reason = item.reason
        _require_text(
            reason,
            f"authorization.decisions[{index}].reason",
            _MAX_POLICY_REASON_LENGTH,
        )
        request = item.request
        if type(request) is not CapabilityRequest:
            raise ValueError("Malformed authorization: request must be CapabilityRequest.")
        canonical_request = _canonical_request(
            request,
            f"authorization.decisions[{index}].request",
        )
        error = _request_value_error(canonical_request) or _category_value_error(
            canonical_request
        )
        if error is not None:
            raise ValueError(f"Malformed authorization: {error}.")
        canonical.append(PolicyDecision(canonical_request, item.decision, reason))
    return Authorization(tuple(canonical))


def _request_value_error(request: CapabilityRequest) -> str | None:
    checks = (
        _text_error(request.request_id, "request_id", 36),
        _text_error(request.action, "action", _MAX_ACTION_LENGTH),
        _text_error(request.target, "target", _MAX_TARGET_LENGTH),
        _text_error(request.justification, "justification", _MAX_JUSTIFICATION_LENGTH),
    )
    for error in checks:
        if error is not None:
            return error
    if not _REQUEST_ID_RE.fullmatch(request.request_id):
        return "request_id must match cap- followed by 32 lowercase hexadecimal characters"
    if not _valid_confidence(request.confidence):
        return "confidence must be a finite non-boolean number between 0 and 1"
    for index, item in enumerate(request.evidence):
        source_error = _text_error(item.source, f"evidence[{index}].source", _MAX_EVIDENCE_SOURCE_LENGTH)
        if source_error is not None:
            return source_error
        detail_error = _text_error(item.detail, f"evidence[{index}].detail", _MAX_EVIDENCE_DETAIL_LENGTH)
        if detail_error is not None:
            return detail_error
        if item.line is not None and (
            type(item.line) is not int
            or not 1 <= item.line <= _MAX_LINE_NUMBER
        ):
            return f"evidence[{index}].line must be null or a positive bounded integer"
    return None


def _category_value_error(request: CapabilityRequest) -> str | None:
    """Reject secret-bearing or ambiguous target shapes before reporting them."""

    if request.category == CapabilityCategory.NETWORK:
        if request.target in {"<dynamic>", "<invalid-network-target>"}:
            return None
        try:
            parsed = urlparse(f"//{request.target}")
            host = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port
        except ValueError:
            return "network target must be one canonical lowercase hostname[:port]"
        canonical = f"{host}:{port}" if port is not None else host
        if (
            not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or request.target != canonical
        ):
            return "network target must be one canonical lowercase hostname[:port]"
    return None


def _require_text(value: object, field: str, maximum: int) -> None:
    error = _text_error(value, field, maximum)
    if error is not None:
        raise ValueError(f"Malformed execution plan: {error}.")


def _text_error(value: object, field: str, maximum: int) -> str | None:
    if type(value) is not str:
        return f"{field} must be a string"
    if not value:
        return f"{field} must not be empty"
    if len(value) > maximum:
        return f"{field} exceeds {maximum} characters"
    if "\x00" in value:
        return f"{field} must not contain NUL"
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return f"{field} must be valid UTF-8 text without lone surrogates"
    return None


def _valid_confidence(value: object) -> bool:
    if type(value) not in {int, float}:
        return False
    try:
        numeric = float(value)
    except (OverflowError, TypeError, ValueError):
        return False
    return math.isfinite(numeric) and 0.0 <= numeric <= 1.0
