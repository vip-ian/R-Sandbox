"""Combine static evidence and shadow-execution events into a verdict."""

from __future__ import annotations

import posixpath
from urllib.parse import urlparse

from r_sandbox.models import (
    AgentOutcome,
    Authorization,
    Decision,
    ExecutionResult,
    Finding,
    RiskLevel,
    RuntimeEvidenceSource,
    SecurityAssessment,
    SecurityVerdict,
    canonical_execution_result,
    canonical_findings,
)
from r_sandbox.policy.proposal_validation import canonical_authorization


_WEIGHTS = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 5,
    RiskLevel.HIGH: 20,
    RiskLevel.CRITICAL: 45,
}


class SecurityAssessor:
    """Evidence-based security preflight, not a proof that code is benign."""

    def assess(
        self,
        findings: tuple[Finding, ...],
        authorization: Authorization,
        execution: ExecutionResult | None,
        warnings: tuple[str, ...] = (),
    ) -> SecurityAssessment:
        findings = canonical_findings(findings)
        authorization = canonical_authorization(authorization)
        if execution is not None:
            execution = canonical_execution_result(execution)
        reasons: list[str] = []
        score = sum(_WEIGHTS[item.risk] for item in findings)
        critical = any(item.risk == RiskLevel.CRITICAL for item in findings)
        high = any(item.risk == RiskLevel.HIGH for item in findings)

        blocked_runtime = (
            []
            if execution is None
            else [
                event
                for event in execution.events
                if not event.allowed
                and event.event_type.lower()
                in {
                    "filesystem",
                    "network",
                    "process",
                    "secret",
                    "device",
                    "side_effect",
                    "resource",
                }
            ]
        )
        score += min(40, 15 * len(blocked_runtime))
        if blocked_runtime:
            reasons.append(f"Shadow execution recorded {len(blocked_runtime)} blocked project behavior(s).")

        denied_observations = [
            item for item in authorization.decisions if item.decision == Decision.DENY
        ]
        if denied_observations:
            reasons.append(
                f"Static analysis found {len(denied_observations)} behavior(s) outside the minimum-authority contract."
            )
        if critical:
            reasons.append("At least one critical secret or exfiltration indicator was found.")
        elif high:
            reasons.append("At least one high-risk behavior requires review.")

        score = min(100, score)
        pending_download_hosts = {
            _network_endpoint(item.request.target)
            for item in authorization.decisions
            if item.request.category.value == "network"
            and item.request.action.lower() == "download"
            and item.decision == Decision.REQUIRE_APPROVAL
        }
        pending_download_hosts.discard("")
        allowed_requests = tuple(
            item.request
            for item in authorization.decisions
            if item.decision == Decision.ALLOW
        )
        authorized_download_hosts = {
            _network_endpoint(request.target)
            for request in allowed_requests
            if request.category.value == "network"
            and request.action.lower() == "download"
        }
        authorized_download_hosts.discard("")
        expected_download_hosts = pending_download_hosts | authorized_download_hosts
        sensitive_static_secret_access = any(
            item.decision == Decision.DENY
            and item.request.category.value == "secret"
            and item.request.risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}
            for item in authorization.decisions
        )
        def is_dangerous(event) -> bool:
            return (
                event.event_type.lower() in {"secret", "side_effect", "device"}
                or (
                    event.event_type.lower() == "network"
                    and (
                        event.action.lower()
                        in {"send", "post", "put", "patch", "upload"}
                        or _network_endpoint(event.target) not in expected_download_hosts
                        or sensitive_static_secret_access
                    )
                )
                or (
                    event.event_type.lower() == "filesystem"
                    and (
                        not _sandbox_scratch_target(event.target)
                        and (
                            event.action.lower()
                            in {"delete", "delete_or_move", "rename", "mutate", "write"}
                            or any(
                                marker in event.target.lower()
                                for marker in (
                                    ".ssh",
                                    ".aws",
                                    ".env",
                                    "credential",
                                    "secret",
                                    "/etc/passwd",
                                    "/etc/shadow",
                                )
                            )
                        )
                    )
                )
                or (
                    event.event_type.lower() == "process"
                    and (
                        event.action.lower() != "execute"
                        or not any(
                            request.category.value == "process"
                            and request.action == "execute"
                            and request.target == event.target
                            for request in allowed_requests
                        )
                    )
                )
            )

        def event_is_authorized(event) -> bool:
            event_type = event.event_type.lower()
            action = event.action.lower()
            target = event.target
            if event_type in {"observer", "runtime", "dry_run", "policy"}:
                return True
            if event_type == "filesystem":
                return _authorized_filesystem_event(action, target, allowed_requests)
            if event_type == "network":
                if action not in {"connect", "download"}:
                    return False
                endpoint = _network_endpoint(target)
                return any(
                    request.category.value == "network"
                    and request.action == "download"
                    and _network_endpoint(request.target) == endpoint
                    and endpoint != ""
                    for request in allowed_requests
                )
            if event_type == "process":
                return any(
                    request.category.value == "process"
                    and request.action == action
                    and request.target == target
                    for request in allowed_requests
                )
            if event_type == "device":
                return any(
                    request.category.value == "device"
                    and request.action == action
                    and request.target.lower() == target.lower()
                    for request in allowed_requests
                )
            if event_type == "resource":
                return action != "limit"
            return False

        runtime_events = () if execution is None else execution.events
        completed_contract_violations = tuple(
            event
            for event in runtime_events
            if event.allowed and not event_is_authorized(event)
        )
        trusted_runtime_sources = {
            RuntimeEvidenceSource.SUPERVISOR,
            RuntimeEvidenceSource.INDEPENDENT_OBSERVER,
        }
        target_reported_contract_violation = any(
            event.source == RuntimeEvidenceSource.TARGET_TELEMETRY
            for event in completed_contract_violations
        )
        dangerous_runtime = any(
            is_dangerous(event)
            and not event_is_authorized(event)
            and event.source in trusted_runtime_sources
            for event in runtime_events
        )
        target_reported_danger = any(
            is_dangerous(event)
            and not event_is_authorized(event)
            and event.source == RuntimeEvidenceSource.TARGET_TELEMETRY
            for event in runtime_events
        )
        generic_independent_contract_violation = any(
            event.source in trusted_runtime_sources and not is_dangerous(event)
            for event in completed_contract_violations
        )
        if completed_contract_violations:
            reasons.append(
                f"Runtime evidence recorded {len(completed_contract_violations)} "
                "completed behavior(s) outside the authorized contract."
            )
        if dangerous_runtime:
            score = min(100, score + 30)
            reasons.append(
                "Independent runtime evidence recorded a high-impact attempted or completed behavior."
            )
        if target_reported_danger:
            score = min(100, score + 10)
            reasons.append(
                "Target-controlled telemetry reported high-impact behavior; it is "
                "review evidence, not an independently attested unsafe verdict."
            )
        if generic_independent_contract_violation:
            score = min(100, score + 10)
            reasons.append(
                "Independent runtime evidence recorded a completed, lower-impact "
                "behavior outside the authorized contract."
            )
        elif target_reported_contract_violation and not target_reported_danger:
            reasons.append(
                "Target-controlled telemetry reported behavior outside the contract; "
                "independent confirmation is required."
            )
        resource_contract_breach = any(
            event.event_type.lower() == "resource"
            and event.action.lower() == "limit"
            for event in blocked_runtime
        )
        if resource_contract_breach:
            reasons.append(
                "Shadow execution exceeded an approved resource or output contract."
            )
        attestation_claimed = execution is not None and any(
            event.event_type.lower() == "observer"
            and event.action == "coverage_attestation"
            for event in execution.events
        )
        incomplete_observation = (
            execution is not None
            and any(event.event_type.lower() == "observer" for event in execution.events)
        )
        if incomplete_observation:
            reasons.append("The runtime evidence channel was missing, invalid, or bypassed.")
        if attestation_claimed:
            reasons.append(
                "Coverage-attestation events are not accepted until a typed, "
                "run-bound independent observer contract is implemented."
            )
        analysis_incomplete = bool(warnings)
        if analysis_incomplete:
            reasons.append(
                f"Static analysis reported {len(warnings)} coverage warning(s); unexamined behavior may remain."
            )
        runtime_unavailable = execution is not None and execution.status.value == "runtime_unavailable"
        completed = (
            execution is not None
            and execution.status == AgentOutcome.SUCCEEDED
            and execution.exit_code == 0
        )
        # Provenance alone is insufficient: no attestation is yet bound to the
        # snapshot, image, platform, argv, and unique run. Therefore no event
        # can satisfy independent coverage in the current MVP.
        independently_observed = False
        if completed and not independently_observed:
            reasons.append(
                "SAFE is reserved for runs with an independent host-side behavior-coverage attestation."
            )

        if dangerous_runtime:
            verdict = SecurityVerdict.UNSAFE
            summary = "Shadow execution attempted secret access, egress, or another high-impact contract violation."
        elif resource_contract_breach:
            verdict = SecurityVerdict.REVIEW
            summary = (
                "Shadow execution exceeded an approved resource boundary and requires review."
            )
        elif target_reported_danger:
            verdict = SecurityVerdict.REVIEW
            summary = (
                "The target-reported trace contains a high-impact behavior claim that "
                "requires independent confirmation."
            )
        elif completed_contract_violations:
            verdict = SecurityVerdict.REVIEW
            summary = (
                "Runtime evidence contains behavior outside the authorized contract "
                "that requires review."
            )
        elif runtime_unavailable:
            verdict = SecurityVerdict.REVIEW if (critical or high) else SecurityVerdict.INCONCLUSIVE
            summary = "The isolated runtime was unavailable, so the project was not dynamically verified."
        elif denied_observations:
            verdict = SecurityVerdict.REVIEW
            summary = (
                "Static analysis found behavior outside the enforced minimum-authority "
                "contract; a successful exit cannot clear it."
            )
        elif incomplete_observation:
            verdict = SecurityVerdict.REVIEW if (critical or high) else SecurityVerdict.INCONCLUSIVE
            summary = "The shadow run completed without a trustworthy behavior trace."
        elif analysis_incomplete:
            verdict = SecurityVerdict.REVIEW if (critical or high) else SecurityVerdict.INCONCLUSIVE
            summary = "Static-analysis coverage was incomplete, so the project cannot be marked safe."
        elif blocked_runtime or critical or high or score >= 20:
            verdict = SecurityVerdict.REVIEW
            summary = "The project needs human review before it is trusted for research use."
        elif execution is None:
            verdict = SecurityVerdict.INCONCLUSIVE
            summary = "Static preflight completed; a sandboxed shadow run is still required."
        elif completed and independently_observed:
            verdict = SecurityVerdict.SAFE
            summary = "No contract-violating behavior was observed under the tested path and inputs."
            reasons.append("A safe verdict applies only to the exercised execution path and supplied inputs.")
        elif completed:
            verdict = SecurityVerdict.INCONCLUSIVE
            summary = (
                "The shadow run completed inside the sandbox, but the current Python audit "
                "telemetry is target-controlled and cannot independently prove benign behavior."
            )
        else:
            verdict = SecurityVerdict.INCONCLUSIVE
            summary = "Shadow execution did not complete and produced no decisive security violation."

        return SecurityAssessment(
            verdict=verdict,
            risk_score=score,
            summary=summary,
            reasons=tuple(reasons),
            static_findings=findings,
            runtime_events=() if execution is None else execution.events,
        )


def _network_endpoint(target: str) -> str:
    """Return the exact normalized endpoint; an omitted port means HTTPS/443."""

    try:
        parsed = urlparse(f"//{target}")
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError:
        return ""
    if (
        not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65_535)
    ):
        return ""
    return f"{host}:{443 if port is None else port}"


def _sandbox_scratch_target(target: str) -> bool:
    normalized = _canonical_runtime_path(target)
    if normalized is None:
        return False
    return any(
        normalized == root or normalized.startswith(root + "/")
        for root in ("/output", "/tmp", "/dev/shm")
    )


def _authorized_filesystem_event(action: str, target: str, requests) -> bool:
    normalized = _canonical_runtime_path(target)
    if normalized is None:
        return False
    read_actions = {"read", "list", "stat"}
    write_actions = {"write", "create", "delete", "delete_or_move", "rename", "mutate"}
    runtime_read_roots = ("/usr", "/lib", "/lib64", "/opt/r-sandbox-audit")
    safe_device_reads = {"/dev/null", "/dev/random", "/dev/urandom"}
    if action in read_actions and normalized in safe_device_reads:
        return True
    if action in read_actions and any(
        normalized == root or normalized.startswith(root + "/")
        for root in runtime_read_roots
    ):
        return True
    scopes = (
        ("<repository>", "/workspace"),
        ("<output>", "/output"),
        ("<temporary>", "/tmp"),
        ("<shared-memory>", "/dev/shm"),
    )
    for abstract, root in scopes:
        if normalized != root and not normalized.startswith(root + "/"):
            continue
        required_action = "read" if action in read_actions else "write" if action in write_actions else action
        return any(
            request.category.value == "filesystem"
            and request.target == abstract
            and request.action == required_action
            for request in requests
        )
    return False


def _canonical_runtime_path(target: str) -> str | None:
    """Return an unambiguous absolute POSIX observer path or fail closed."""

    if (
        not isinstance(target, str)
        or not target.startswith("/")
        or target.startswith("//")
        or "\\" in target
        or "\x00" in target
        or " -> " in target
    ):
        return None
    components = target.split("/")
    if ".." in components:
        return None
    normalized = posixpath.normpath(target)
    if not normalized.startswith("/") or normalized.startswith("//"):
        return None
    return normalized
