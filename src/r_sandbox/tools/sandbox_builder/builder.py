"""Translate policy authorization into a concrete, restrictive sandbox spec."""

from __future__ import annotations

import math
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from ...models import (
    Authorization,
    CapabilityCategory,
    Decision,
    PlanStep,
    ResourceLimits,
    SandboxSpec,
)
from ...policy.proposal_validation import canonical_authorization, canonical_plan_step


_IMAGE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}\Z")
_SAFE_EXECUTABLES = frozenset({"python", "python3"})


class SandboxBuildError(ValueError):
    """The authorized plan cannot be represented by the safe runtime."""


class UnauthorizedCapabilityError(SandboxBuildError):
    """A step contains a capability without a matching policy decision."""


class PendingApprovalError(SandboxBuildError):
    """Compatibility error for callers that prohibit shadow execution."""


class DeniedCapabilityError(SandboxBuildError):
    """Compatibility error for callers that prohibit shadow execution."""


@dataclass(slots=True)
class SandboxBuilder:
    """Create :class:`SandboxSpec` from policy decisions for a shadow run.

    The builder never executes repository code.  The repository is exposed as
    a read-only mount and the fresh output directory as the sole persistent
    host-backed read/write mount. Bounded private /tmp and /dev/shm scratch
    filesystems are separately authorized, and
    environment variables are empty unless a future trusted layer explicitly
    extends the shared contract. Denied and approval-pending capabilities do
    not abort the shadow run: they are deliberately not granted so attempted
    behavior can be observed against the restrictive boundary.
    """

    default_limits: ResourceLimits = field(default_factory=ResourceLimits)

    def build(
        self,
        repository: Path,
        output: Path,
        step: PlanStep,
        authorization: Authorization,
        image: str = "python:3.11-slim",
        *,
        limits: ResourceLimits | None = None,
        require_fresh_output: bool = False,
    ) -> SandboxSpec:
        """Validate authorization and return a least-privilege specification."""

        try:
            step = canonical_plan_step(step)
            authorization = canonical_authorization(authorization)
        except ValueError as error:
            raise SandboxBuildError(str(error)) from error
        repository_path = self._existing_directory(repository, "repository")
        self._validate_step(step, repository_path)
        self._validate_image(image)
        selected_limits = limits or self.default_limits
        self._validate_limits(selected_limits)

        decisions_by_id = {}
        for policy_decision in authorization.decisions:
            request_id = policy_decision.request.request_id
            if request_id in decisions_by_id:
                raise SandboxBuildError(
                    f"authorization contains duplicate request id: {request_id}"
                )
            decisions_by_id[request_id] = policy_decision

        allowed_requests = []
        for request in step.capabilities:
            policy_decision = decisions_by_id.get(request.request_id)
            if policy_decision is None:
                raise UnauthorizedCapabilityError(
                    f"no policy decision for capability: {request.request_id}"
                )
            if policy_decision.request != request:
                raise UnauthorizedCapabilityError(
                    "authorized capability payload differs from the planned "
                    f"request: {request.request_id}"
                )
            if policy_decision.decision in {Decision.REQUIRE_APPROVAL, Decision.DENY}:
                # Shadow execution is fail-closed. The runtime receives no
                # representation of this capability, then records attempts.
                continue
            if policy_decision.decision != Decision.ALLOW:
                raise UnauthorizedCapabilityError(
                    f"unsupported policy decision for: {request.request_id}"
                )
            # Derive grants from the detached policy-side snapshot rather than
            # retaining any semantic producer object.
            allowed_requests.append(policy_decision.request)

        self._require_filesystem_grant(
            allowed_requests,
            target="<repository>",
            action="read",
            description="read-only repository mount",
        )
        self._require_filesystem_grant(
            allowed_requests,
            target="<output>",
            action="read",
            description="read access on the output mount",
        )
        self._require_filesystem_grant(
            allowed_requests,
            target="<output>",
            action="write",
            description="write access on the output mount",
        )
        self._require_filesystem_grant(
            allowed_requests,
            target="<temporary>",
            action="read",
            description="read access on bounded ephemeral /tmp",
        )
        self._require_filesystem_grant(
            allowed_requests,
            target="<temporary>",
            action="write",
            description="write access on bounded ephemeral /tmp",
        )
        self._require_filesystem_grant(
            allowed_requests,
            target="<shared-memory>",
            action="read",
            description="read access on bounded private /dev/shm",
        )
        self._require_filesystem_grant(
            allowed_requests,
            target="<shared-memory>",
            action="write",
            description="write access on bounded private /dev/shm",
        )
        self._require_resource_grants(allowed_requests, selected_limits)

        executable = step.argv[0]
        process_granted = any(
            request.category == CapabilityCategory.PROCESS
            and request.action == "execute"
            and request.target == executable
            for request in allowed_requests
        )
        if not process_granted:
            raise UnauthorizedCapabilityError(
                "container argv[0] is not bound to an allowed process capability"
            )

        supplied_output = Path(output)
        try:
            supplied_metadata = supplied_output.lstat()
        except FileNotFoundError:
            supplied_metadata = None
        except OSError as error:
            raise SandboxBuildError(
                f"output path could not be inspected safely: {output}"
            ) from error
        if supplied_metadata is not None and _is_link_or_reparse(
            supplied_output, supplied_metadata
        ):
            raise SandboxBuildError(
                "output must not be a link, junction, or reparse point"
            )
        output_candidate = supplied_output.resolve(strict=False)
        if (
            repository_path == output_candidate
            or output_candidate.is_relative_to(repository_path)
            or repository_path.is_relative_to(output_candidate)
        ):
            raise SandboxBuildError(
                "repository and output must be disjoint directories; a nested "
                "writable mount would mutate or overexpose the source tree"
            )
        output_path = self._output_directory(
            output_candidate,
            require_new=require_fresh_output,
        )
        self._validate_mount_path(repository_path, "repository")
        self._validate_mount_path(output_path, "output")

        network_targets = tuple(
            dict.fromkeys(
                request.target
                for request in allowed_requests
                if request.category == CapabilityCategory.NETWORK
            )
        )
        devices = tuple(
            dict.fromkeys(
                request.target
                for request in allowed_requests
                if request.category == CapabilityCategory.DEVICE
                and request.action == "access"
            )
        )
        return SandboxSpec(
            repository=str(repository_path),
            output=str(output_path),
            image=image,
            argv=step.argv,
            network_targets=network_targets,
            environment=(),
            devices=devices,
            limits=selected_limits,
            read_only_root=True,
            drop_capabilities=True,
        )

    @staticmethod
    def _require_filesystem_grant(
        requests,
        *,
        target: str,
        action: str,
        description: str,
    ) -> None:
        if not any(
            request.category == CapabilityCategory.FILESYSTEM
            and request.target == target
            and request.action == action
            for request in requests
        ):
            raise UnauthorizedCapabilityError(
                f"{description} has no matching ALLOW capability"
            )

    @staticmethod
    def _require_resource_grants(requests, limits: ResourceLimits) -> None:
        granted: dict[str, float] = {}
        for request in requests:
            if request.category != CapabilityCategory.RESOURCE:
                continue
            if not isinstance(request.target, str):
                continue
            try:
                value = float(request.target)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(value) or value <= 0:
                continue
            if request.action in {
                "memory_mb",
                "pids",
                "timeout_seconds",
                "output_mb",
                "output_files",
                "temporary_mb",
                "shared_memory_mb",
            } and not value.is_integer():
                continue
            granted[request.action] = max(granted.get(request.action, 0.0), value)
        required = {
            "cpu": float(limits.cpus),
            "memory_mb": float(limits.memory_mb),
            "pids": float(limits.pids),
            "timeout_seconds": float(limits.timeout_seconds),
            "output_mb": float(limits.output_mb),
            "output_files": float(limits.output_files),
            "temporary_mb": float(limits.temporary_mb),
            "shared_memory_mb": float(limits.shared_memory_mb),
        }
        for action, value in required.items():
            if action not in granted or value > granted[action]:
                raise UnauthorizedCapabilityError(
                    f"resource grant {action}={value:g} exceeds or lacks a matching ALLOW capability"
                )

    @staticmethod
    def _validate_step(step: PlanStep, repository: Path) -> None:
        if not step.argv or not step.argv[0]:
            raise SandboxBuildError("the plan step must contain a non-empty argv")
        if any(not isinstance(argument, str) or "\x00" in argument for argument in step.argv):
            raise SandboxBuildError("argv must contain only NUL-free strings")
        executable = Path(step.argv[0]).name.lower()
        if executable not in _SAFE_EXECUTABLES or step.argv[0] != executable:
            raise SandboxBuildError("only a bare, allowlisted research executable is supported")
        if executable in {"python", "python3"}:
            if len(step.argv) < 2:
                raise SandboxBuildError("Python execution requires a repository script or module")
            if step.argv[1] == "-m":
                if len(step.argv) < 3 or not re.fullmatch(
                    r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", step.argv[2]
                ):
                    raise SandboxBuildError("invalid Python module entrypoint")
                module_path = Path(*step.argv[2].split("."))
                candidates = (
                    repository / module_path.with_suffix(".py"),
                    repository / module_path / "__main__.py",
                )
                if not any(_safe_repository_file(repository, item) for item in candidates):
                    raise SandboxBuildError("Python module entrypoint is not in the repository")
            else:
                if step.argv[1].startswith("-"):
                    raise SandboxBuildError("Python interpreter flags are not accepted at the runtime boundary")
                if not _safe_repository_file(repository, repository / step.argv[1]):
                    raise SandboxBuildError("Python script entrypoint is not a regular repository file")
        if step.cwd.rstrip("/") != "/workspace":
            raise SandboxBuildError(
                "the current SandboxSpec contract can safely represent only "
                "cwd=/workspace"
            )
        request_ids = [request.request_id for request in step.capabilities]
        if len(request_ids) != len(set(request_ids)):
            raise SandboxBuildError("the plan step contains duplicate capability ids")

    @staticmethod
    def _validate_image(image: str) -> None:
        if not isinstance(image, str) or not _IMAGE_PATTERN.fullmatch(image):
            raise SandboxBuildError(f"invalid container image reference: {image!r}")

    @staticmethod
    def _validate_limits(limits: ResourceLimits) -> None:
        if not isinstance(limits, ResourceLimits):
            raise SandboxBuildError("resource limits must use the ResourceLimits model")
        if not _valid_positive_number(limits.cpus):
            raise SandboxBuildError("CPU limit must be a positive finite number")
        integer_limits = (
            ("memory", limits.memory_mb),
            ("PID", limits.pids),
            ("timeout", limits.timeout_seconds),
            ("output byte", limits.output_mb),
            ("output file", limits.output_files),
            ("temporary storage", limits.temporary_mb),
            ("shared memory", limits.shared_memory_mb),
        )
        for label, value in integer_limits:
            if not _valid_positive_integer(value):
                raise SandboxBuildError(
                    f"{label} limit must be a positive finite integer"
                )

    @staticmethod
    def _existing_directory(path: Path, label: str) -> Path:
        try:
            resolved = Path(path).resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise SandboxBuildError(f"{label} directory does not exist: {path}") from error
        if not resolved.is_dir():
            raise SandboxBuildError(f"{label} is not a directory: {resolved}")
        return resolved

    @staticmethod
    def _output_directory(path: Path, *, require_new: bool = False) -> Path:
        candidate = Path(path).resolve(strict=False)
        created = False
        try:
            candidate.mkdir(parents=True, mode=0o700, exist_ok=False)
            created = True
        except FileExistsError:
            if require_new:
                raise SandboxBuildError(
                    "run output directory already exists; refusing to mount "
                    "preexisting content"
                )
        except OSError as error:
            raise SandboxBuildError(f"cannot prepare output directory: {path}") from error
        try:
            metadata = candidate.lstat()
            if _is_link_or_reparse(candidate, metadata):
                raise SandboxBuildError(
                    "output must not be a link, junction, or reparse point"
                )
            if not stat.S_ISDIR(metadata.st_mode):
                raise SandboxBuildError(f"output is not a directory: {candidate}")
            if created:
                _prepare_new_output_identity(candidate)
            resolved = candidate.resolve(strict=True)
            _require_runtime_output_access(resolved)
        except SandboxBuildError:
            if created:
                try:
                    candidate.rmdir()
                except OSError:
                    pass
            raise
        except (OSError, RuntimeError) as error:
            if created:
                try:
                    candidate.rmdir()
                except OSError:
                    pass
            raise SandboxBuildError(f"cannot prepare output directory: {path}") from error
        return resolved

    @staticmethod
    def _validate_mount_path(path: Path, label: str) -> None:
        # Docker's --mount value is comma-delimited.  Reject ambiguous source
        # paths instead of attempting an escaping scheme that varies by daemon.
        if any(character in str(path) for character in (",", "\n", "\r", "\x00")):
            raise SandboxBuildError(
                f"{label} path cannot be represented safely as a Docker mount: {path}"
            )


def _safe_repository_file(repository: Path, candidate: Path) -> bool:
    try:
        if candidate.is_symlink():
            return False
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(repository)
    except (OSError, RuntimeError, ValueError):
        return False
    return resolved.is_file()


def _is_link_or_reparse(path: Path, metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode):
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            if is_junction():
                return True
        except OSError:
            return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _runtime_identity() -> tuple[int, int] | None:
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if not callable(getuid) or not callable(getgid):
        return None
    uid, gid = int(getuid()), int(getgid())
    return (uid, gid) if uid > 0 else (65534, 65534)


def _valid_positive_number(value: object) -> bool:
    if type(value) not in {int, float}:
        return False
    try:
        numeric = float(value)
    except (OverflowError, TypeError, ValueError):
        return False
    return math.isfinite(numeric) and numeric > 0


def _valid_positive_integer(value: object) -> bool:
    return type(value) is int and value > 0


def _prepare_new_output_identity(output: Path) -> None:
    identity = _runtime_identity()
    if identity is None:
        return
    uid, gid = identity
    try:
        if int(os.getuid()) == 0:
            os.chown(output, uid, gid, follow_symlinks=False)
        os.chmod(output, 0o700, follow_symlinks=False)
    except OSError as error:
        raise SandboxBuildError(
            "new output directory could not be assigned to the sandbox user"
        ) from error


def _require_runtime_output_access(output: Path) -> None:
    identity = _runtime_identity()
    if identity is None:
        return
    uid, gid = identity
    metadata = output.stat(follow_symlinks=False)
    if uid == metadata.st_uid:
        permissions = (metadata.st_mode >> 6) & 0o7
    elif gid == metadata.st_gid:
        permissions = (metadata.st_mode >> 3) & 0o7
    else:
        permissions = metadata.st_mode & 0o7
    if permissions & 0o7 != 0o7:
        raise SandboxBuildError(
            "existing output directory is not readable, writable, and searchable "
            f"by sandbox uid/gid {uid}:{gid}; refusing recursive chmod or chown"
        )
