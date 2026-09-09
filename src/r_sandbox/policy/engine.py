"""Fail-closed policy evaluation.

The semantic layer can explain why a permission might be useful.  This module
is intentionally boring: it accepts only narrowly modelled capabilities,
validates their targets, and never lets an approval override a hard denial.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
from pathlib import Path, PurePosixPath
import ipaddress
import re
from urllib.parse import urlparse

from r_sandbox.models import (
    Authorization,
    CapabilityCategory,
    CapabilityRequest,
    Decision,
    ExecutionPlan,
    PolicyDecision,
    RiskLevel,
)
from r_sandbox.policy.identity import capability_request_id
from r_sandbox.policy.proposal_validation import (
    quarantine_request,
    validate_execution_plan,
)


_SAFE_EXECUTABLES = frozenset({"python", "python3"})
_HOST_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def _configured_network_endpoint(target: str) -> str:
    """Normalize a trusted CLI/config allow entry to an exact endpoint."""

    try:
        parsed = urlparse(f"//{target.lower()}")
        port = parsed.port
    except (AttributeError, ValueError) as error:
        raise ValueError("network_allowlist contains a malformed endpoint") from error
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not _HOST_RE.fullmatch(host)
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise ValueError(
            "network_allowlist entries must be hostname[:port] values with ports in 1..65535"
        )
    return f"{host}:{443 if port is None else port}"


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    repository: Path
    output: Path
    approved_request_ids: frozenset[str] = field(default_factory=frozenset)
    network_allowlist: frozenset[str] = field(default_factory=frozenset)
    allowed_executables: frozenset[str] = field(default_factory=lambda: _SAFE_EXECUTABLES)
    max_cpus: float = 2.0
    max_memory_mb: int = 4096
    max_pids: int = 256
    max_timeout_seconds: int = 1800
    max_output_mb: int = 4096
    max_output_files: int = 50_000
    max_temporary_mb: int = 512
    max_shared_memory_mb: int = 512
    repository_digest: str = ""
    authorization_context: str = ""
    approval_context_immutable: bool = True

    def normalized(self) -> "PolicyConfig":
        if type(self.approval_context_immutable) is not bool:
            raise ValueError("approval_context_immutable must be an exact boolean")
        for name, values in (
            ("approved_request_ids", self.approved_request_ids),
            ("network_allowlist", self.network_allowlist),
            ("allowed_executables", self.allowed_executables),
        ):
            if type(values) is not frozenset or len(values) > 10_000 or any(
                type(item) is not str
                or not item
                or len(item) > 8_192
                or "\x00" in item
                for item in values
            ):
                raise ValueError(f"{name} must be a bounded frozenset of exact strings")
        for name, value in (
            ("repository_digest", self.repository_digest),
            ("authorization_context", self.authorization_context),
        ):
            if type(value) is not str or len(value) > 32_768 or "\x00" in value:
                raise ValueError(f"{name} must be an exact bounded string")
        return PolicyConfig(
            repository=self.repository.resolve(strict=True),
            output=self.output.resolve(strict=False),
            repository_digest=self.repository_digest,
            authorization_context=self.authorization_context,
            approval_context_immutable=self.approval_context_immutable,
            approved_request_ids=self.approved_request_ids,
            network_allowlist=frozenset(
                _configured_network_endpoint(target)
                for target in self.network_allowlist
            ),
            allowed_executables=self.allowed_executables,
            max_cpus=self.max_cpus,
            max_memory_mb=self.max_memory_mb,
            max_pids=self.max_pids,
            max_timeout_seconds=self.max_timeout_seconds,
            max_output_mb=self.max_output_mb,
            max_output_files=self.max_output_files,
            max_temporary_mb=self.max_temporary_mb,
            max_shared_memory_mb=self.max_shared_memory_mb,
        )


class PolicyEngine:
    """Turn a proposed plan into explicit allow/deny/approval decisions."""

    def authorize(self, plan: ExecutionPlan, config: PolicyConfig) -> Authorization:
        validated_plan = validate_execution_plan(plan)
        canonical_plan = validated_plan.plan
        validated_requests = validated_plan.requests
        if any(item.error is not None for item in validated_requests):
            return Authorization(
                tuple(
                    PolicyDecision(
                        (
                            quarantine_request(item.request, item.error, index)
                            if item.error is not None
                            else item.request
                        ),
                        Decision.DENY,
                        (
                            f"Malformed capability proposal: {item.error}."
                            if item.error is not None
                            else "Authorization aborted because the plan contains a malformed capability proposal."
                        ),
                    )
                    for index, item in enumerate(validated_requests)
                )
            )

        cfg = config.normalized()
        config_error = _numeric_config_error(cfg)
        decisions: list[PolicyDecision] = []
        seen: set[str] = set()
        for item in validated_requests:
            request = item.request
            if request.request_id in seen:
                continue
            seen.add(request.request_id)
            if config_error is not None:
                decisions.append(
                    PolicyDecision(request, Decision.DENY, config_error)
                )
                continue
            if not _valid_confidence(request.confidence):
                decisions.append(
                    PolicyDecision(
                        request,
                        Decision.DENY,
                        "Capability confidence must be a finite number between 0 and 1.",
                    )
                )
                continue
            expected_id = capability_request_id(
                cfg.repository,
                canonical_plan.goal,
                request.category,
                request.action,
                request.target,
                request.risk,
                request.confidence,
                cfg.repository_digest,
                request.justification,
                request.evidence,
                cfg.authorization_context,
            )
            if request.request_id != expected_id:
                decisions.append(
                    PolicyDecision(
                        request,
                        Decision.DENY,
                        "Capability id is not bound to this repository, goal, and canonical payload.",
                    )
                )
                continue
            decision, reason = self._evaluate(request, cfg)
            if (
                decision == Decision.REQUIRE_APPROVAL
                and request.request_id in cfg.approved_request_ids
            ):
                if cfg.approval_context_immutable:
                    decision = Decision.ALLOW
                    reason = "Explicit approval supplied for this exact request id and immutable execution context."
                else:
                    reason = (
                        "Approval was not applied because the execution image is not "
                        "bound to an immutable sha256 digest."
                    )
            decisions.append(PolicyDecision(request, decision, reason))
        return Authorization(tuple(decisions))

    def _evaluate(self, request: CapabilityRequest, cfg: PolicyConfig) -> tuple[Decision, str]:
        handlers = {
            CapabilityCategory.FILESYSTEM: self._filesystem,
            CapabilityCategory.NETWORK: self._network,
            CapabilityCategory.PROCESS: self._process,
            CapabilityCategory.SECRET: self._secret,
            CapabilityCategory.DEVICE: self._device,
            CapabilityCategory.RESOURCE: self._resource,
            CapabilityCategory.SIDE_EFFECT: self._side_effect,
        }
        handler = handlers.get(request.category)
        if handler is None:
            return Decision.DENY, "Unknown capability category; policy is fail-closed."
        return handler(request, cfg)

    @staticmethod
    def _filesystem(request: CapabilityRequest, cfg: PolicyConfig) -> tuple[Decision, str]:
        action = request.action.lower()
        target = request.target
        output_actions = {
            "read",
            "write",
            "create",
            "list",
            "stat",
            "delete_or_move",
            "rename",
            "mutate",
        }
        if target in {"<repository>", "/workspace"}:
            if action in {"read", "list", "stat"}:
                return Decision.ALLOW, "The repository is mounted read-only."
            return Decision.DENY, "The original repository is immutable during execution."
        if target in {"<output>", "/output"}:
            if action in output_actions:
                return Decision.ALLOW, "Access is confined to fresh per-run output artifacts."
            return Decision.DENY, "Unsupported operation on the output mount."
        if target in {"<temporary>", "/tmp", "<shared-memory>", "/dev/shm"}:
            if action in output_actions:
                return Decision.ALLOW, "Access is confined to bounded ephemeral container storage."
            return Decision.DENY, "Unsupported operation on ephemeral storage."

        # Static analysis normally reports paths as they appear in source.  Map
        # relative paths into /workspace, but reject traversal before resolving.
        pure = PurePosixPath(target.replace("\\", "/"))
        if ".." in pure.parts:
            return Decision.DENY, "Path traversal is never authorized."
        if pure.is_absolute() and str(pure).startswith("/output/"):
            if action in output_actions:
                return Decision.ALLOW, "Access is confined to fresh per-run output artifacts."
            return Decision.DENY, "Unsupported operation on the output mount."
        if pure.is_absolute() and (
            str(pure).startswith("/tmp/")
            or str(pure).startswith("/dev/shm/")
        ):
            if action in output_actions:
                return Decision.ALLOW, "Access is confined to bounded ephemeral container storage."
            return Decision.DENY, "Unsupported operation on ephemeral storage."
        sensitive = {".ssh", ".aws", ".gnupg", ".env", "credentials", "id_rsa"}
        if any(part.lower() in sensitive for part in pure.parts):
            return Decision.DENY, "Credential and secret-bearing paths are outside the research contract."
        if pure.is_absolute():
            if str(pure).startswith("/workspace/") and action in {"read", "list", "stat"}:
                return Decision.ALLOW, "Read is confined to the repository mount."
            return Decision.DENY, "Absolute host paths are not exposed to the sandbox."
        if action in {"read", "list", "stat"}:
            return Decision.ALLOW, "Relative reads resolve inside the read-only repository."
        return Decision.DENY, (
            "Writes must target /output explicitly; relative output aliases are "
            "not mounted by the current runtime."
        )

    @staticmethod
    def _network(request: CapabilityRequest, cfg: PolicyConfig) -> tuple[Decision, str]:
        action = request.action.lower()
        try:
            parsed = urlparse(f"//{request.target}")
            port = parsed.port
        except ValueError:
            return Decision.DENY, "Malformed network targets are never authorized."
        host = (parsed.hostname or "").lower().rstrip(".")
        canonical_target = f"{host}:{port}" if port is not None else host
        if (
            not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or request.target != canonical_target
            or (port is not None and not 1 <= port <= 65_535)
        ):
            return Decision.DENY, "Network targets must be one canonical lowercase hostname[:port]."
        if not host or host in {"*", "0.0.0.0", "localhost"} or not _HOST_RE.fullmatch(host):
            return Decision.DENY, "Network access requires one concrete public hostname."
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address and (address.is_private or address.is_loopback or address.is_link_local):
            return Decision.DENY, "Private, loopback, and link-local destinations are never exposed."
        if action in {"post", "put", "upload", "send", "connect_unknown"}:
            return Decision.DENY, "Potential data egress is not approvable in the MVP policy."
        if action != "download":
            return Decision.DENY, "Unknown or non-download network actions are denied by default."
        if request.confidence < 0.65:
            return Decision.DENY, "The requested destination is not sufficiently related to the stated research goal."
        endpoint = f"{host}:{443 if port is None else port}"
        if endpoint in cfg.network_allowlist:
            return Decision.ALLOW, "Exact endpoint is present in the explicit run allowlist."
        return Decision.REQUIRE_APPROVAL, "Network is off by default; approve this exact endpoint to continue."

    @staticmethod
    def _process(request: CapabilityRequest, cfg: PolicyConfig) -> tuple[Decision, str]:
        if request.action.lower() != "execute":
            return Decision.DENY, "Unsupported process capability."
        executable = request.target
        if (
            executable in _SAFE_EXECUTABLES
            and executable in cfg.allowed_executables
            and request.risk in {RiskLevel.LOW, RiskLevel.MEDIUM}
        ):
            return Decision.ALLOW, "Executable is in the narrow research-runtime allowlist."
        return Decision.DENY, "Arbitrary subprocess execution is outside the sandbox contract."

    @staticmethod
    def _secret(request: CapabilityRequest, _cfg: PolicyConfig) -> tuple[Decision, str]:
        return Decision.DENY, "Host secrets are never passed to untrusted research code."

    @staticmethod
    def _device(request: CapabilityRequest, cfg: PolicyConfig) -> tuple[Decision, str]:
        if request.action.lower() != "access":
            return Decision.DENY, "Device inspection cannot be isolated from full device access."
        if request.target.lower() not in {"gpu", "cuda"}:
            return Decision.DENY, "Arbitrary host devices are never exposed."
        if request.confidence < 0.65:
            return Decision.DENY, "GPU access is not justified by the stated research goal."
        return Decision.REQUIRE_APPROVAL, "GPU access requires explicit approval."

    @staticmethod
    def _resource(request: CapabilityRequest, cfg: PolicyConfig) -> tuple[Decision, str]:
        if not isinstance(request.target, str):
            return Decision.DENY, "Resource limits must be finite numeric strings."
        try:
            value = float(request.target)
        except (TypeError, ValueError):
            return Decision.DENY, "Resource limits must be finite numeric strings."
        if not math.isfinite(value):
            return Decision.DENY, "Resource limits must be finite numeric strings."
        action = request.action.lower()
        if action in {
            "memory_mb",
            "pids",
            "timeout_seconds",
            "output_mb",
            "output_files",
            "temporary_mb",
            "shared_memory_mb",
        } and not value.is_integer():
            return Decision.DENY, "This resource limit must be a whole number."
        maximums = {
            "cpu": cfg.max_cpus,
            "memory_mb": float(cfg.max_memory_mb),
            "pids": float(cfg.max_pids),
            "timeout_seconds": float(cfg.max_timeout_seconds),
            "output_mb": float(cfg.max_output_mb),
            "output_files": float(cfg.max_output_files),
            "temporary_mb": float(cfg.max_temporary_mb),
            "shared_memory_mb": float(cfg.max_shared_memory_mb),
        }
        maximum = maximums.get(action)
        if maximum is None or value <= 0 or value > maximum:
            return Decision.DENY, "Requested resource is unknown or exceeds the configured ceiling."
        return Decision.ALLOW, "Request is within the configured resource ceiling."

    @staticmethod
    def _side_effect(request: CapabilityRequest, _cfg: PolicyConfig) -> tuple[Decision, str]:
        if request.action.lower() in {"delete", "overwrite", "publish", "push", "upload", "external_write"}:
            return Decision.DENY, "Irreversible or external side effects are forbidden."
        return Decision.DENY, "Unknown or dynamic side effects are denied by default."


def _valid_confidence(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        numeric = float(value)
    except (OverflowError, TypeError, ValueError):
        return False
    return math.isfinite(numeric) and 0.0 <= numeric <= 1.0


def _numeric_config_error(config: PolicyConfig) -> str | None:
    numeric_fields: tuple[tuple[str, object, bool], ...] = (
        ("max_cpus", config.max_cpus, False),
        ("max_memory_mb", config.max_memory_mb, True),
        ("max_pids", config.max_pids, True),
        ("max_timeout_seconds", config.max_timeout_seconds, True),
        ("max_output_mb", config.max_output_mb, True),
        ("max_output_files", config.max_output_files, True),
        ("max_temporary_mb", config.max_temporary_mb, True),
        ("max_shared_memory_mb", config.max_shared_memory_mb, True),
    )
    for name, value, integer_only in numeric_fields:
        valid_type = isinstance(value, int if integer_only else (int, float))
        try:
            numeric = float(value) if valid_type and not isinstance(value, bool) else None
        except (OverflowError, TypeError, ValueError):
            numeric = None
        if numeric is None or not math.isfinite(numeric) or numeric <= 0:
            return (
                f"Policy ceiling {name} must be a positive finite "
                + ("integer." if integer_only else "number.")
            )
    return None
