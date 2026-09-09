"""Safely translate a :class:`SandboxSpec` into a Docker CLI invocation."""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import stat
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from queue import Empty, SimpleQueue
from typing import BinaryIO, Callable, Protocol

from ...models import (
    AgentOutcome,
    ExecutionResult,
    ResourceLimits,
    RuntimeEvent,
    RuntimeEvidenceSource,
    SandboxSpec,
)
from ..runtime_observer.manifest import (
    ManifestLimitExceeded,
    capture_output_manifest,
)


_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_IMAGE_REFERENCE = re.compile(
    r"(?:[a-zA-Z0-9._-]+(?::[0-9]+)?/)*"
    r"[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)*"
    r"(?::[a-zA-Z0-9._-]+)?"
    r"(?:@sha256:[a-fA-F0-9]{64})?\Z"
)
_DOCKER_PLATFORM = "linux/amd64"
_CONTAINER_ID = re.compile(rb"[a-f0-9]{64}\r?\n?\Z")
_DOCKER_CLI_ENVIRONMENT_ALLOWLIST = frozenset(
    {"COMSPEC", "LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "WINDIR"}
)
_DOCKER_ROUTING_ENVIRONMENT = frozenset(
    {
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_CERT_PATH",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
    }
)


class ExecutionPolicyError(ValueError):
    """A specification cannot be enforced safely by this supervisor."""


class UnsupportedNetworkPolicy(ExecutionPolicyError):
    """Docker alone cannot enforce a domain-scoped egress allowlist."""


class ExecutionSupervisor(Protocol):
    """Common interface for real and dry-run execution backends."""

    def execute(self, spec: SandboxSpec) -> ExecutionResult:
        """Execute or safely simulate one sandbox specification."""


class _BoundedHeadTailBuffer:
    """Retain bounded output while counting and draining every byte."""

    __slots__ = (
        "_head",
        "_head_limit",
        "_limit",
        "_tail",
        "_tail_limit",
        "_total_bytes",
    )

    def __init__(self, limit: int) -> None:
        if limit < 0:
            raise ValueError("output capture limit cannot be negative")
        self._limit = limit
        self._head_limit = limit // 2
        self._tail_limit = limit - self._head_limit
        self._head = bytearray()
        self._tail = bytearray()
        self._total_bytes = 0

    def feed(self, chunk: bytes) -> None:
        """Consume a chunk without retaining more than the configured limit."""

        self._total_bytes += len(chunk)
        head_remaining = self._head_limit - len(self._head)
        if head_remaining > 0:
            take = min(head_remaining, len(chunk))
            self._head.extend(chunk[:take])
            chunk = chunk[take:]
        if not chunk or self._tail_limit == 0:
            return
        if len(chunk) >= self._tail_limit:
            self._tail[:] = chunk[-self._tail_limit :]
            return
        overflow = len(self._tail) + len(chunk) - self._tail_limit
        if overflow > 0:
            del self._tail[:overflow]
        self._tail.extend(chunk)

    def render(self) -> str:
        retained = len(self._head) + len(self._tail)
        if self._total_bytes <= retained:
            return bytes(self._head + self._tail).decode("utf-8", errors="replace")
        omitted = self._total_bytes - retained
        head = bytes(self._head).decode("utf-8", errors="replace")
        tail = bytes(self._tail).decode("utf-8", errors="replace")
        return f"{head}\n...[truncated {omitted} bytes]...\n{tail}"


@dataclass(frozen=True, slots=True)
class _OutputMonitorFailure:
    event: RuntimeEvent
    cleanup_detail: str = ""
    termination_detail: str = ""

    def with_shutdown(
        self,
        cleanup_detail: str,
        termination_detail: str,
    ) -> "_OutputMonitorFailure":
        return _OutputMonitorFailure(
            event=self.event,
            cleanup_detail=cleanup_detail,
            termination_detail=termination_detail,
        )


@dataclass(frozen=True, slots=True)
class _ContainerCleanup:
    detail: str
    confirmed: bool


def _drain_stream(
    stream: BinaryIO,
    capture: _BoundedHeadTailBuffer,
    label: str,
    errors: SimpleQueue[str],
) -> None:
    """Drain one child pipe to EOF, retaining only a bounded head and tail."""

    try:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            capture.feed(chunk)
    except Exception as error:  # pragma: no cover - OS pipe failures are rare.
        errors.put(f"{label} drain failed with {type(error).__name__}")
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _check_output_budget(
    output: Path,
    spec: SandboxSpec,
) -> _OutputMonitorFailure | None:
    try:
        manifest = capture_output_manifest(
            output,
            max_files=spec.limits.output_files,
            max_total_bytes=spec.limits.output_mb * 1024 * 1024,
        )
        if not manifest.exists:
            raise OSError("designated output directory disappeared")
    except ManifestLimitExceeded as error:
        if error.limit_name == "max_files":
            target = "output_files"
            configured = spec.limits.output_files
        elif error.limit_name == "max_total_bytes":
            target = "output_mb"
            configured = spec.limits.output_mb
        else:
            return _OutputMonitorFailure(
                RuntimeEvent(
                    event_type="observer",
                    action="output_scan",
                    target="fresh-output",
                    allowed=False,
                    detail=(
                        "Best-effort output monitor could not complete its bounded "
                        "scan because an internal traversal limit was reached."
                    )[:500],
                    source=RuntimeEvidenceSource.SUPERVISOR,
                )
            )
        return _OutputMonitorFailure(
            RuntimeEvent(
                event_type="resource",
                action="limit",
                target=target,
                allowed=False,
                detail=(
                    f"Best-effort output monitor exceeded {target}={configured} "
                    f"(observed at least {error.observed})."
                )[:500],
                source=RuntimeEvidenceSource.SUPERVISOR,
            )
        )
    except (OSError, RuntimeError, ValueError) as error:
        return _OutputMonitorFailure(
            RuntimeEvent(
                event_type="observer",
                action="output_scan",
                target="fresh-output",
                allowed=False,
                detail=(
                    "Best-effort output monitor failed closed: "
                    f"{type(error).__name__}; target-derived path text was omitted."
                )[:500],
                source=RuntimeEvidenceSource.SUPERVISOR,
            )
        )
    return None


def _monitor_output(
    output: Path,
    spec: SandboxSpec,
    stop: threading.Event,
    interval_seconds: float,
    failures: SimpleQueue[_OutputMonitorFailure],
    stop_sandbox: Callable[[], tuple[str, str]],
) -> None:
    """Best-effort monitor; bind mounts have no portable hard quota."""

    try:
        while True:
            failure = _check_output_budget(output, spec)
            if failure is not None:
                cleanup_detail, termination_detail = stop_sandbox()
                failures.put(
                    failure.with_shutdown(cleanup_detail, termination_detail)
                )
                return
            if stop.wait(interval_seconds):
                # Close the last write-vs-poll race with one final bounded scan.
                failure = _check_output_budget(output, spec)
                if failure is not None:
                    cleanup_detail, termination_detail = stop_sandbox()
                    failures.put(
                        failure.with_shutdown(cleanup_detail, termination_detail)
                    )
                return
    except BaseException as error:
        failure = _OutputMonitorFailure(
            RuntimeEvent(
                event_type="observer",
                action="output_scan",
                target=str(output),
                allowed=False,
                detail=(
                    "Best-effort output monitor failed closed after an unexpected "
                    f"{type(error).__name__}."
                ),
                source=RuntimeEvidenceSource.SUPERVISOR,
            )
        )
        try:
            cleanup_detail, termination_detail = stop_sandbox()
        except BaseException as cleanup_error:  # last-resort thread containment
            cleanup_detail = (
                "Container cleanup raised an unexpected "
                f"{type(cleanup_error).__name__}."
            )
            termination_detail = "Docker client termination was not confirmed."
        failures.put(failure.with_shutdown(cleanup_detail, termination_detail))


def _docker_command(
    spec: SandboxSpec,
    *,
    docker_binary: str,
    container_name: str,
) -> tuple[str, ...]:
    spec = _canonical_spec_snapshot(spec)
    _validate_enforceable_spec(spec)
    docker_config = _trusted_docker_config_directory()
    command = [
        docker_binary,
        "--config",
        str(docker_config),
        "--host",
        _local_docker_endpoint(),
        "create",
        "--platform",
        _DOCKER_PLATFORM,
        "--pull",
        "never",
        "--name",
        container_name,
        "--label",
        "io.r-sandbox.managed=true",
        "--label",
        f"io.r-sandbox.run-id={container_name}",
        "--init",
        "--no-healthcheck",
        "--log-driver",
        "none",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--cpus",
        _format_number(spec.limits.cpus),
        "--memory",
        f"{spec.limits.memory_mb}m",
        "--memory-swap",
        f"{spec.limits.memory_mb}m",
        "--memory-swappiness",
        "0",
        "--pids-limit",
        str(spec.limits.pids),
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={spec.limits.temporary_mb}m",
        "--shm-size",
        f"{spec.limits.shared_memory_mb}m",
        "--ulimit",
        "core=0:0",
        "--mount",
        f"type=bind,source={spec.repository},target=/workspace,readonly",
        "--mount",
        f"type=bind,source={spec.output},target=/output",
        "--workdir",
        "/workspace",
    ]
    if not spec.devices:
        # Do not inherit a daemon-wide NVIDIA default runtime or CUDA-image
        # enumeration variables when no device capability was authorized.
        # NVIDIA documents `void` as runc-equivalent even under its runtime;
        # the explicit runc selection is the primary enforcement boundary.
        command.extend(
            (
                "--runtime",
                "runc",
                "--env",
                "NVIDIA_VISIBLE_DEVICES=void",
                "--env",
                "NVIDIA_DRIVER_CAPABILITIES=",
                "--env",
                "CUDA_VISIBLE_DEVICES=",
            )
        )
    name_index = command.index("--name")
    command[name_index + 2:name_index + 2] = _container_user_arguments()
    if _is_python_execution(spec.argv):
        audit_directory = _python_audit_directory()
        if any(
            character in str(audit_directory)
            for character in (",", "\n", "\r", "\x00")
        ):
            raise ExecutionPolicyError(
                "Python audit-hook path cannot be represented safely as a Docker mount"
            )
        command.extend(
            (
                "--mount",
                f"type=bind,source={audit_directory},target=/opt/r-sandbox-audit,readonly",
                "--env",
                "PYTHONPATH=/opt/r-sandbox-audit",
                "--env",
                "PYTHONSAFEPATH=1",
                "--env",
                "PYTHONNOUSERSITE=1",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                "--env",
                f"R_SANDBOX_EVENT_LOG={_audit_log_container_path(container_name)}",
                "--env",
                f"R_SANDBOX_RUN_ID={container_name}",
                "--env",
                "R_SANDBOX_SHADOW_MODE=1",
            )
        )
    if spec.devices:
        # The policy/builder permit only the typed GPU capability. Never pass
        # an agent-provided string to Docker's arbitrary --device option.
        command.extend(("--gpus", "all"))
    # Docker normally preserves an image's ENTRYPOINT and treats our argv as
    # mere arguments to it.  Override it so the executable authorized by the
    # policy is exactly the executable that starts in the container.
    command.extend(("--entrypoint", spec.argv[0]))
    command.append(spec.image)
    if _is_python_execution(spec.argv):
        # Python 3.11+'s -P prevents /workspace (the script/cwd directory)
        # from preceding the trusted audit mount during sitecustomize import.
        command.append("-P")
    command.extend(spec.argv[1:])
    return tuple(command)


def _docker_start_command(
    docker_binary: Path,
    container_id: str,
) -> tuple[str, ...]:
    return (
        str(docker_binary),
        "--config",
        str(_trusted_docker_config_directory()),
        "--host",
        _local_docker_endpoint(),
        "start",
        "--attach",
        container_id,
    )


def _canonical_spec_snapshot(spec: SandboxSpec) -> SandboxSpec:
    """Copy an exact primitive-only contract before validation/serialization."""

    try:
        if type(spec) is not SandboxSpec:
            raise TypeError("sandbox spec must use the exact SandboxSpec type")
        limits = spec.limits
        if type(limits) is not ResourceLimits:
            raise TypeError("sandbox limits must use the exact ResourceLimits type")
        limits_snapshot = ResourceLimits(
            cpus=limits.cpus,
            memory_mb=limits.memory_mb,
            pids=limits.pids,
            timeout_seconds=limits.timeout_seconds,
            output_mb=limits.output_mb,
            output_files=limits.output_files,
            temporary_mb=limits.temporary_mb,
            shared_memory_mb=limits.shared_memory_mb,
        )
        return SandboxSpec(
            repository=spec.repository,
            output=spec.output,
            image=spec.image,
            argv=spec.argv,
            source_repository=spec.source_repository,
            snapshot_digest=spec.snapshot_digest,
            network_targets=spec.network_targets,
            environment=spec.environment,
            devices=spec.devices,
            limits=limits_snapshot,
            read_only_root=spec.read_only_root,
            drop_capabilities=spec.drop_capabilities,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise ExecutionPolicyError(f"malformed sandbox contract: {error}") from error


def _validate_enforceable_spec(spec: SandboxSpec) -> None:
    if spec.network_targets:
        targets = ", ".join(spec.network_targets)
        raise UnsupportedNetworkPolicy(
            "domain-scoped egress is not enforceable with Docker's basic network "
            f"modes ({targets}); configure a policy-aware egress proxy first"
        )
    if not spec.read_only_root:
        raise ExecutionPolicyError("a writable container root filesystem is not allowed")
    if not spec.drop_capabilities:
        raise ExecutionPolicyError("Linux capability dropping may not be disabled")
    if not spec.argv or not spec.argv[0]:
        raise ExecutionPolicyError("container argv must be non-empty")
    if not _IMAGE_REFERENCE.fullmatch(spec.image) or spec.image.startswith("-"):
        raise ExecutionPolicyError("container image reference is malformed or unsafe")
    if any("\x00" in value for value in spec.argv):
        raise ExecutionPolicyError("container argv contains a NUL byte")
    executable = Path(spec.argv[0]).name.lower()
    if executable not in {"python", "python3"} or spec.argv[0] != executable:
        raise ExecutionPolicyError("container executable is outside the runtime allowlist")
    if executable in {"python", "python3"}:
        if len(spec.argv) < 2:
            raise ExecutionPolicyError("Python execution requires a repository entrypoint")
        if spec.argv[1] == "-m":
            if len(spec.argv) < 3 or not re.fullmatch(
                r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", spec.argv[2]
            ):
                raise ExecutionPolicyError("Python module entrypoint is invalid")
        elif spec.argv[1].startswith("-"):
            # CPython continues option parsing across multiple flags. Merely
            # checking argv[1] for -S/-c lets a harmless-looking -B prefix hide
            # a later telemetry bypass option.
            raise ExecutionPolicyError(
                "Python interpreter flags are forbidden at the supervisor boundary"
            )
    for label, raw_path in (("repository", spec.repository), ("output", spec.output)):
        path = Path(raw_path)
        if not path.is_absolute() or not path.is_dir():
            raise ExecutionPolicyError(f"{label} must be an existing absolute directory")
        if any(character in raw_path for character in (",", "\n", "\r", "\x00")):
            raise ExecutionPolicyError(f"{label} path is unsafe for Docker --mount")
    repository = Path(spec.repository).resolve()
    output = Path(spec.output).resolve()
    if repository == output or output.is_relative_to(repository) or repository.is_relative_to(output):
        raise ExecutionPolicyError("repository and output mounts must be disjoint")
    _validate_python_repository_entrypoint(spec.argv, repository)
    _require_runtime_output_access(output)
    if not _valid_positive_number(spec.limits.cpus):
        raise ExecutionPolicyError("CPU limit must be a positive finite number")
    integer_limits = (
        ("memory", spec.limits.memory_mb),
        ("PID", spec.limits.pids),
        ("timeout", spec.limits.timeout_seconds),
        ("output byte", spec.limits.output_mb),
        ("output file", spec.limits.output_files),
        ("temporary storage", spec.limits.temporary_mb),
        ("shared memory", spec.limits.shared_memory_mb),
    )
    for label, value in integer_limits:
        if not _valid_positive_integer(value):
            raise ExecutionPolicyError(
                f"{label} limit must be a positive finite integer"
            )
    for name, _value in spec.environment:
        if not _ENVIRONMENT_NAME.fullmatch(name):
            raise ExecutionPolicyError(f"invalid environment variable name: {name!r}")
        if name.upper() in _DOCKER_ROUTING_ENVIRONMENT:
            raise ExecutionPolicyError(
                f"Docker daemon/context routing variable is forbidden: {name}"
            )
        if _is_python_execution(spec.argv) and name in {
            "PYTHONPATH",
            "PYTHONSAFEPATH",
            "PYTHONNOUSERSITE",
            "PYTHONDONTWRITEBYTECODE",
            "R_SANDBOX_EVENT_LOG",
            "R_SANDBOX_RUN_ID",
            "R_SANDBOX_SHADOW_MODE",
        }:
            raise ExecutionPolicyError(
                f"environment variable is reserved by the Python audit layer: {name}"
            )
    if spec.environment:
        raise ExecutionPolicyError(
            "custom environment forwarding has no enforceable capability model in this MVP"
        )
    for device in spec.devices:
        if device.lower() not in {"gpu", "cuda"}:
            raise ExecutionPolicyError(f"unsupported host device capability: {device!r}")


def _validate_python_repository_entrypoint(
    argv: tuple[str, ...],
    repository: Path,
) -> None:
    if argv[1] == "-m":
        module_path = Path(*argv[2].split("."))
        candidates = (
            repository / module_path.with_suffix(".py"),
            repository / module_path / "__main__.py",
        )
    else:
        raw = argv[1]
        portable = PurePosixPath(raw)
        if (
            portable.is_absolute()
            or not portable.parts
            or ".." in portable.parts
            or "\\" in raw
        ):
            raise ExecutionPolicyError(
                "Python script entrypoint must be a relative repository path"
            )
        candidates = (repository.joinpath(*portable.parts),)
    if not any(_safe_repository_entrypoint(repository, candidate) for candidate in candidates):
        raise ExecutionPolicyError("Python entrypoint is not a regular repository file")


def _safe_repository_entrypoint(repository: Path, candidate: Path) -> bool:
    try:
        metadata = candidate.lstat()
        if _is_link_or_reparse(candidate, metadata) or not stat.S_ISREG(metadata.st_mode):
            return False
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(repository)
    except (OSError, RuntimeError, ValueError):
        return False
    return resolved.is_file()


@dataclass(frozen=True, slots=True)
class DryRunExecutionSupervisor:
    """Produce the exact safe Docker argv without starting a process."""

    docker_binary: str = "docker"

    def __post_init__(self) -> None:
        if (
            type(self.docker_binary) is not str
            or not self.docker_binary
            or len(self.docker_binary) > 32_768
            or "\x00" in self.docker_binary
        ):
            raise TypeError("docker_binary must be an exact bounded string")

    def execute(self, spec: SandboxSpec) -> ExecutionResult:
        started = time.monotonic()
        try:
            spec = _canonical_spec_snapshot(spec)
            command = _docker_command(
                spec,
                docker_binary=self.docker_binary,
                container_name="r-sandbox-dry-run",
            )
        except ExecutionPolicyError as error:
            return _blocked_result(error, started)
        event = RuntimeEvent(
            event_type="dry_run",
            action="preview",
            target=spec.image,
            allowed=True,
            detail="No target code was executed.",
            source=RuntimeEvidenceSource.SUPERVISOR,
        )
        return ExecutionResult(
            status=AgentOutcome.PLANNED,
            exit_code=None,
            duration_seconds=time.monotonic() - started,
            events=(event,),
            command_preview=command,
        )


@dataclass(frozen=True, slots=True)
class DockerExecutionSupervisor:
    """Run target argv only inside a hardened Docker container.

    Every subprocess call uses an argument vector with ``shell=False``.  Docker
    receives a generated container name so a timed-out run can be forcefully
    removed without touching unrelated containers.

    Output limits are a best-effort host-side monitor, not a portable hard
    quota for a bind mount. A target can temporarily exceed a limit between
    polls; deployments needing strict prevention must use a quota-capable
    dedicated filesystem or storage driver.
    """

    docker_binary: str = "docker"
    max_output_chars: int = 1_000_000
    cleanup_timeout_seconds: int = 10
    output_poll_interval_seconds: float = 0.25

    def __post_init__(self) -> None:
        if (
            type(self.docker_binary) is not str
            or not self.docker_binary
            or len(self.docker_binary) > 32_768
            or "\x00" in self.docker_binary
        ):
            raise TypeError("docker_binary must be an exact bounded string")
        if (
            type(self.max_output_chars) is not int
            or not 0 <= self.max_output_chars <= 1_000_000
        ):
            raise TypeError("max_output_chars must be an exact integer in 0..1000000")
        if (
            type(self.cleanup_timeout_seconds) is not int
            or not 1 <= self.cleanup_timeout_seconds <= 60
        ):
            raise TypeError(
                "cleanup_timeout_seconds must be an exact integer in 1..60"
            )
        if (
            not _valid_positive_number(self.output_poll_interval_seconds)
            or self.output_poll_interval_seconds > 60
        ):
            raise TypeError(
                "output_poll_interval_seconds must be an exact finite number in (0, 60]"
            )

    def command_preview(self, spec: SandboxSpec) -> tuple[str, ...]:
        """Return a deterministic, redaction-safe preview without execution."""

        spec = _canonical_spec_snapshot(spec)
        return _docker_command(
            spec,
            docker_binary=self.docker_binary,
            container_name="r-sandbox-preview",
        )

    def execute(self, spec: SandboxSpec) -> ExecutionResult:
        started = time.monotonic()
        container_name = f"r-sandbox-{uuid.uuid4().hex}"
        try:
            spec = _canonical_spec_snapshot(spec)
            _validate_enforceable_spec(spec)
            _trusted_docker_config_directory()
            ambient_routing = _ambient_docker_routing_variables()
            if ambient_routing:
                raise ExecutionPolicyError(
                    "Ambient Docker daemon/context routing is forbidden: "
                    + ", ".join(ambient_routing)
                )
            if (
                isinstance(self.max_output_chars, bool)
                or not isinstance(self.max_output_chars, int)
                or self.max_output_chars < 0
            ):
                raise ExecutionPolicyError("output capture limit cannot be negative")
            if (
                not _valid_positive_number(self.output_poll_interval_seconds)
                or self.output_poll_interval_seconds > 60
            ):
                raise ExecutionPolicyError(
                    "output monitor interval must be between 0 and 60 seconds"
                )
            if not _valid_positive_integer(self.cleanup_timeout_seconds):
                raise ExecutionPolicyError(
                    "Docker control-command timeout must be a positive integer"
                )
        except ExecutionPolicyError as error:
            return _blocked_result(error, started)

        preview = _docker_command(
            spec,
            docker_binary=self.docker_binary,
            container_name=container_name,
        )
        resolved_binary = _resolve_docker_binary(
            self.docker_binary,
            forbidden=(Path(spec.repository), Path(spec.output), Path.cwd()),
        )
        if resolved_binary is None:
            detail = f"Docker executable is unavailable: {self.docker_binary}"
            return ExecutionResult(
                status=AgentOutcome.RUNTIME_UNAVAILABLE,
                exit_code=None,
                stderr=detail,
                duration_seconds=time.monotonic() - started,
                events=(
                    RuntimeEvent(
                        event_type="runtime",
                        action="invoke",
                        target=self.docker_binary,
                        allowed=False,
                        detail=detail,
                        source=RuntimeEvidenceSource.SUPERVISOR,
                    ),
                ),
                command_preview=preview,
            )
        command = _docker_command(
            spec,
            docker_binary=str(resolved_binary),
            container_name=container_name,
        )
        try:
            _verify_image_has_no_declared_volumes(
                resolved_binary,
                spec.image,
                timeout_seconds=self.cleanup_timeout_seconds,
            )
        except ExecutionPolicyError as error:
            return _blocked_result(error, started)
        if _is_python_execution(spec.argv):
            try:
                _prepare_python_audit_log(Path(spec.output), container_name)
            except ExecutionPolicyError as error:
                return _blocked_result(error, started)
        preflight_output_failure = _check_output_budget(Path(spec.output), spec)
        if preflight_output_failure is not None:
            return _output_monitor_result(
                preflight_output_failure,
                started=started,
                command=command,
                exit_code=None,
            )

        child_environment = _docker_cli_environment()
        try:
            creation = subprocess.run(
                command,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=min(self.cleanup_timeout_seconds, 10),
                check=False,
                env=child_environment,
                cwd=str(resolved_binary.parent),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            detail = (
                "Docker container creation could not be confirmed: "
                f"{type(error).__name__}."
            )
            events = (
                RuntimeEvent(
                    event_type="runtime",
                    action="create",
                    target="sandbox-container",
                    allowed=False,
                    detail=detail,
                    source=RuntimeEvidenceSource.SUPERVISOR,
                ),
            )
            events += (
                RuntimeEvent(
                    event_type="observer",
                    action="container_ownership",
                    target="sandbox-container",
                    allowed=False,
                    detail=(
                        "No container id was obtained; name-based deletion was refused "
                        "because ownership could not be proven."
                    ),
                    source=RuntimeEvidenceSource.SUPERVISOR,
                ),
            )
            return ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=None,
                stderr=detail,
                duration_seconds=time.monotonic() - started,
                events=events,
                command_preview=command,
            )
        if creation.returncode != 0:
            detail = (
                "Docker container creation failed with exit code "
                f"{creation.returncode}."
            )
            events = (
                RuntimeEvent(
                    event_type="runtime",
                    action="create",
                    target="sandbox-container",
                    allowed=False,
                    detail=detail,
                    source=RuntimeEvidenceSource.SUPERVISOR,
                ),
            )
            return ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=None,
                stderr=detail,
                duration_seconds=time.monotonic() - started,
                events=events,
                command_preview=command,
            )

        created_stdout = creation.stdout
        if type(created_stdout) is not bytes or not _CONTAINER_ID.fullmatch(
            created_stdout
        ):
            cleanup = _safe_remove_named_container(
                self, container_name, resolved_binary
            )
            detail = "Docker create returned an invalid container identity."
            events = (
                RuntimeEvent(
                    event_type="observer",
                    action="container_identity",
                    target="sandbox-container",
                    allowed=False,
                    detail=detail,
                    source=RuntimeEvidenceSource.SUPERVISOR,
                ),
            )
            if not cleanup.confirmed:
                events += (_cleanup_failure_event(cleanup.detail),)
            return ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=None,
                stderr="\n".join((detail, cleanup.detail)),
                duration_seconds=time.monotonic() - started,
                events=events,
                command_preview=command,
            )
        container_id = created_stdout.strip().decode("ascii")

        return self._start_owned_container(
            spec=spec,
            command=command,
            container_name=container_name,
            container_id=container_id,
            resolved_binary=resolved_binary,
            child_environment=child_environment,
            started=started,
        )

    def _start_owned_container(
        self,
        *,
        spec: SandboxSpec,
        command: tuple[str, ...],
        container_name: str,
        container_id: str,
        resolved_binary: Path,
        child_environment: dict[str, str],
        started: float,
    ) -> ExecutionResult:
        """Transfer one created container to supervision without an orphan gap."""

        process: subprocess.Popen[bytes] | None = None
        lifecycle_resolved = False
        try:
            start_command = _docker_start_command(resolved_binary, container_id)
            stdout_capture = _BoundedHeadTailBuffer(self.max_output_chars)
            stderr_capture = _BoundedHeadTailBuffer(self.max_output_chars)
            drain_errors: SimpleQueue[str] = SimpleQueue()
            try:
                process = subprocess.Popen(
                    start_command,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=child_environment,
                    cwd=str(resolved_binary.parent),
                    bufsize=0,
                )
            except (FileNotFoundError, OSError) as error:
                cleanup = _safe_remove_named_container(
                    self, container_id, resolved_binary
                )
                lifecycle_resolved = True
                detail = f"Docker runtime could not be started: {error}"
                events = (
                    RuntimeEvent(
                        event_type="runtime",
                        action="invoke",
                        target=self.docker_binary,
                        allowed=False,
                        detail=detail,
                        source=RuntimeEvidenceSource.SUPERVISOR,
                    ),
                )
                if not cleanup.confirmed:
                    events += (_cleanup_failure_event(cleanup.detail),)
                return ExecutionResult(
                    status=(
                        AgentOutcome.RUNTIME_UNAVAILABLE
                        if cleanup.confirmed
                        else AgentOutcome.FAILED
                    ),
                    exit_code=None,
                    stderr=_truncate(
                        "\n".join((detail, cleanup.detail)), self.max_output_chars
                    ),
                    duration_seconds=time.monotonic() - started,
                    events=events,
                    command_preview=command,
                )

            result = _supervise_started_docker(
                self,
                process=process,
                spec=spec,
                command=command,
                container_name=container_name,
                container_id=container_id,
                resolved_binary=resolved_binary,
                started=started,
                stdout_capture=stdout_capture,
                stderr_capture=stderr_capture,
                drain_errors=drain_errors,
            )
            lifecycle_resolved = True
            return result
        finally:
            if not lifecycle_resolved:
                # Includes BaseException (KeyboardInterrupt/SystemExit) and
                # failures before the inner supervisor installs its own finally.
                if process is not None:
                    try:
                        _terminate_docker_client(process)
                    except BaseException:
                        pass
                _safe_remove_named_container(self, container_id, resolved_binary)

    def _remove_named_container(
        self, container_reference: str, resolved_binary: Path
    ) -> _ContainerCleanup:
        if not resolved_binary.is_absolute():
            return _ContainerCleanup(
                "Container cleanup refused a non-absolute Docker path.", False
            )
        if not re.fullmatch(r"[a-f0-9]{64}", container_reference):
            return _ContainerCleanup(
                "Container cleanup refused a reference that was not the exact "
                "64-character id returned by Docker create.",
                False,
            )
        cleanup_command = (
            str(resolved_binary),
            "--config",
            str(_trusted_docker_config_directory()),
            "--host",
            _local_docker_endpoint(),
            "rm",
            "--force",
            container_reference,
        )
        absence_command = (
            str(resolved_binary),
            "--config",
            str(_trusted_docker_config_directory()),
            "--host",
            _local_docker_endpoint(),
            "container",
            "ls",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"id={container_reference}",
        )
        command_timeout = min(self.cleanup_timeout_seconds, 5)
        last_detail = "Container absence was not confirmed."
        consecutive_absent = 0
        # The client has already been terminated before this method is called.
        # Repeated remove/query rounds close the pending-create race and require
        # stable daemon-side absence rather than trusting one transient lookup.
        for attempt in range(4):
            try:
                cleanup = subprocess.run(
                    cleanup_command,
                    shell=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=command_timeout,
                    check=False,
                    cwd=str(resolved_binary.parent),
                    env=_docker_cli_environment(),
                )
                absence = subprocess.run(
                    absence_command,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=command_timeout,
                    check=False,
                    cwd=str(resolved_binary.parent),
                    env=_docker_cli_environment(),
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                consecutive_absent = 0
                last_detail = (
                    "Container removal/absence verification raised "
                    f"{type(error).__name__}."
                )
            else:
                if absence.returncode == 0 and absence.stdout == b"":
                    consecutive_absent += 1
                    if consecutive_absent >= 2:
                        return _ContainerCleanup(
                            "Named sandbox container absence was confirmed twice.",
                            True,
                        )
                else:
                    consecutive_absent = 0
                    last_detail = (
                        "Container cleanup failed and daemon-side absence was not confirmed "
                        f"(remove={cleanup.returncode}, query={absence.returncode})."
                    )
            if attempt < 3:
                time.sleep(0.05)
        return _ContainerCleanup(last_detail, False)


def _cleanup_failure_event(detail: str) -> RuntimeEvent:
    return RuntimeEvent(
        event_type="observer",
        action="container_teardown",
        target="sandbox-container",
        allowed=False,
        detail=detail[:500] or "Container absence was not confirmed.",
        source=RuntimeEvidenceSource.SUPERVISOR,
    )


def _safe_remove_named_container(
    supervisor: DockerExecutionSupervisor,
    container_reference: str,
    resolved_binary: Path,
) -> _ContainerCleanup:
    try:
        cleanup = supervisor._remove_named_container(
            container_reference, resolved_binary
        )
        if type(cleanup) is not _ContainerCleanup:
            raise TypeError("invalid container-cleanup result")
        return cleanup
    except BaseException as error:
        return _ContainerCleanup(
            "Container cleanup raised an unexpected "
            f"{type(error).__name__}; absence was not confirmed.",
            False,
        )


def _client_termination_failure_event(detail: str) -> RuntimeEvent:
    return RuntimeEvent(
        event_type="observer",
        action="docker_client_teardown",
        target="docker-client",
        allowed=False,
        detail=detail[:500] or "Docker client termination was not confirmed.",
        source=RuntimeEvidenceSource.SUPERVISOR,
    )


def _supervise_started_docker(
    supervisor: DockerExecutionSupervisor,
    *,
    process: subprocess.Popen[bytes],
    spec: SandboxSpec,
    command: tuple[str, ...],
    container_name: str,
    container_id: str,
    resolved_binary: Path,
    started: float,
    stdout_capture: _BoundedHeadTailBuffer,
    stderr_capture: _BoundedHeadTailBuffer,
    drain_errors: SimpleQueue[str],
) -> ExecutionResult:
    """Supervise one launched Docker client with fail-closed teardown."""

    output_monitor_stop = threading.Event()
    output_monitor_failures: SimpleQueue[_OutputMonitorFailure] = SimpleQueue()
    stop_lock = threading.Lock()
    stop_attempted = False
    stop_details = ("", "")
    cleanup_confirmed = False
    stdout_thread: threading.Thread | None = None
    stderr_thread: threading.Thread | None = None
    output_monitor_thread: threading.Thread | None = None
    stdout_started = False
    stderr_started = False
    output_monitor_started = False

    def stop_sandbox() -> tuple[str, str]:
        nonlocal stop_attempted, stop_details, cleanup_confirmed
        with stop_lock:
            if stop_attempted:
                return stop_details
            try:
                termination_detail = _terminate_docker_client(process)
            except BaseException as error:
                termination_detail = (
                    "Docker client termination raised an unexpected "
                    f"{type(error).__name__}."
                )
            cleanup = _safe_remove_named_container(
                supervisor, container_id, resolved_binary
            )
            cleanup_detail = cleanup.detail
            cleanup_confirmed = cleanup.confirmed
            stop_details = (cleanup_detail, termination_detail)
            stop_attempted = True
            return stop_details

    try:
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("Docker client did not provide both output pipes")
        stdout_thread = threading.Thread(
            target=_drain_stream,
            args=(process.stdout, stdout_capture, "stdout", drain_errors),
            name=f"{container_name}-stdout",
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=_drain_stream,
            args=(process.stderr, stderr_capture, "stderr", drain_errors),
            name=f"{container_name}-stderr",
            daemon=True,
        )
        stdout_thread.start()
        stdout_started = True
        stderr_thread.start()
        stderr_started = True

        output_monitor_thread = threading.Thread(
            target=_monitor_output,
            args=(
                Path(spec.output),
                spec,
                output_monitor_stop,
                supervisor.output_poll_interval_seconds,
                output_monitor_failures,
                stop_sandbox,
            ),
            name=f"{container_name}-output-monitor",
            daemon=True,
        )
        output_monitor_thread.start()
        output_monitor_started = True

        timed_out = False
        try:
            returncode = process.wait(timeout=spec.limits.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            returncode = None

        # A Docker CLI return does not prove daemon-side teardown.  Confirm it
        # on every terminal path, including an apparent successful exit.
        cleanup_detail, termination_detail = stop_sandbox()
        lifecycle_events = ()
        if termination_detail:
            lifecycle_events += (
                _client_termination_failure_event(termination_detail),
            )
        if not cleanup_confirmed:
            lifecycle_events += (_cleanup_failure_event(cleanup_detail),)

        output_monitor_stop.set()
        output_monitor_thread.join(
            max(1.0, min(5.0, supervisor.output_poll_interval_seconds * 2))
        )
        output_monitor_failure = _take_output_monitor_failure(
            output_monitor_failures
        )
        if output_monitor_thread.is_alive() and output_monitor_failure is None:
            output_monitor_failure = _OutputMonitorFailure(
                RuntimeEvent(
                    event_type="observer",
                    action="output_scan",
                    target=spec.output,
                    allowed=False,
                    detail=(
                        "Best-effort output monitor did not finish its bounded "
                        "scan after execution stopped."
                    ),
                    source=RuntimeEvidenceSource.SUPERVISOR,
                )
            )

        join_diagnostics = _join_stream_drainers(
            (
                (stdout_thread, process.stdout, "stdout"),
                (stderr_thread, process.stderr, "stderr"),
            )
        )
        drain_diagnostics = _collect_drain_errors(drain_errors) + join_diagnostics
        stdout = stdout_capture.render()
        stderr = stderr_capture.render()
        audit_events = (
            _load_python_audit_events(Path(spec.output), run_id=container_name)
            if _is_python_execution(spec.argv)
            else ()
        )

        if output_monitor_failure is not None:
            return _output_monitor_result(
                output_monitor_failure,
                started=started,
                command=command,
                exit_code=returncode,
                stdout=stdout,
                stderr=stderr,
                drain_diagnostics=drain_diagnostics,
                audit_events=audit_events,
                lifecycle_events=lifecycle_events,
            )

        if timed_out:
            timeout_detail = (
                f"Sandbox exceeded the {spec.limits.timeout_seconds}s timeout."
            )
            stderr = "\n".join(
                part
                for part in (
                    stderr,
                    timeout_detail,
                    cleanup_detail,
                    termination_detail,
                    *drain_diagnostics,
                )
                if part
            )
            events = audit_events + (
                RuntimeEvent(
                    event_type="resource",
                    action="limit",
                    target="timeout",
                    allowed=False,
                    detail=timeout_detail,
                    source=RuntimeEvidenceSource.SUPERVISOR,
                ),
            ) + lifecycle_events + _drain_failure_events(drain_diagnostics)
            return ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=None,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=time.monotonic() - started,
                events=events,
                command_preview=command,
            )

        if drain_diagnostics:
            stderr = "\n".join((stderr, *drain_diagnostics)).strip()
        if lifecycle_events:
            stderr = "\n".join(
                part for part in (stderr, cleanup_detail, termination_detail) if part
            )
        status = AgentOutcome.SUCCEEDED if returncode == 0 else AgentOutcome.FAILED
        exit_code = returncode
        if lifecycle_events and status == AgentOutcome.SUCCEEDED:
            status = AgentOutcome.FAILED
            exit_code = None
        event = RuntimeEvent(
            event_type="process",
            action="execute",
            target=spec.argv[0],
            allowed=True,
            detail=f"Docker exited with code {returncode}.",
            source=RuntimeEvidenceSource.SUPERVISOR,
        )
        return ExecutionResult(
            status=status,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            events=(event,) + audit_events + lifecycle_events + _drain_failure_events(drain_diagnostics),
            command_preview=command,
        )
    except Exception as error:
        cleanup_detail, termination_detail = stop_sandbox()
        detail = (
            "Execution supervisor failed closed after launch due to an unexpected "
            f"{type(error).__name__}."
        )
        events = (
            RuntimeEvent(
                event_type="observer",
                action="lifecycle",
                target="sandbox-container",
                allowed=False,
                detail=detail,
                source=RuntimeEvidenceSource.SUPERVISOR,
            ),
        )
        if not cleanup_confirmed:
            events += (_cleanup_failure_event(cleanup_detail),)
        if termination_detail:
            events += (_client_termination_failure_event(termination_detail),)
        return ExecutionResult(
            status=AgentOutcome.FAILED,
            exit_code=None,
            stderr="\n".join(
                part
                for part in (detail, cleanup_detail, termination_detail)
                if part
            ),
            duration_seconds=time.monotonic() - started,
            events=events,
            command_preview=command,
        )
    finally:
        output_monitor_stop.set()
        if not stop_attempted:
            try:
                stop_sandbox()
            except BaseException:
                pass
        if output_monitor_started and output_monitor_thread is not None:
            try:
                output_monitor_thread.join(1.0)
            except (RuntimeError, OSError):
                pass
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
        for thread, was_started in (
            (stdout_thread, stdout_started),
            (stderr_thread, stderr_started),
        ):
            if was_started and thread is not None:
                try:
                    thread.join(1.0)
                except (RuntimeError, OSError):
                    pass


def _terminate_docker_client(process: subprocess.Popen[bytes]) -> str:
    """Bound the Docker CLI lifetime after its named container is removed."""

    if process.poll() is not None:
        return ""
    try:
        process.terminate()
    except OSError as error:
        return f"Docker client termination failed with {type(error).__name__}."
    try:
        process.wait(timeout=2)
        return ""
    except subprocess.TimeoutExpired:
        pass
    try:
        process.kill()
        process.wait(timeout=2)
        return ""
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"Docker client kill could not be confirmed: {type(error).__name__}."


def _join_stream_drainers(
    drainers: tuple[tuple[threading.Thread, BinaryIO, str], ...],
    *,
    timeout_seconds: float = 5.0,
) -> tuple[str, ...]:
    """Wait a bounded time for EOF after the Docker client has exited."""

    deadline = time.monotonic() + timeout_seconds
    diagnostics: list[str] = []
    for thread, _stream, label in drainers:
        thread.join(max(0.0, deadline - time.monotonic()))
        if thread.is_alive():
            diagnostics.append(
                f"{label} drain did not reach EOF after Docker client exit"
            )
    return tuple(diagnostics)


def _collect_drain_errors(errors: SimpleQueue[str]) -> tuple[str, ...]:
    diagnostics: list[str] = []
    while True:
        try:
            diagnostics.append(errors.get_nowait())
        except Empty:
            return tuple(diagnostics)


def _drain_failure_events(
    diagnostics: tuple[str, ...],
) -> tuple[RuntimeEvent, ...]:
    return tuple(
        RuntimeEvent(
            event_type="observer",
            action="drain",
            target="docker-output",
            allowed=False,
            detail=diagnostic,
            source=RuntimeEvidenceSource.SUPERVISOR,
        )
        for diagnostic in diagnostics
    )


def _take_output_monitor_failure(
    failures: SimpleQueue[_OutputMonitorFailure],
) -> _OutputMonitorFailure | None:
    try:
        return failures.get_nowait()
    except Empty:
        return None


def _output_monitor_result(
    failure: _OutputMonitorFailure,
    *,
    started: float,
    command: tuple[str, ...],
    exit_code: int | None,
    stdout: str = "",
    stderr: str = "",
    drain_diagnostics: tuple[str, ...] = (),
    audit_events: tuple[RuntimeEvent, ...] = (),
    lifecycle_events: tuple[RuntimeEvent, ...] = (),
) -> ExecutionResult:
    stderr = "\n".join(
        part
        for part in (
            stderr,
            failure.event.detail,
            failure.cleanup_detail,
            failure.termination_detail,
            *drain_diagnostics,
        )
        if part
    )
    return ExecutionResult(
        status=AgentOutcome.FAILED,
        exit_code=None if exit_code == 0 else exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=time.monotonic() - started,
        events=(
            audit_events
            + (failure.event,)
            + lifecycle_events
            + _drain_failure_events(drain_diagnostics)
        ),
        command_preview=command,
    )


def _blocked_result(error: ExecutionPolicyError, started: float) -> ExecutionResult:
    target = "network" if isinstance(error, UnsupportedNetworkPolicy) else "sandbox"
    return ExecutionResult(
        status=AgentOutcome.BLOCKED,
        exit_code=None,
        stderr=str(error),
        duration_seconds=time.monotonic() - started,
        events=(
            RuntimeEvent(
                event_type="policy",
                action="enforce",
                target=target,
                allowed=False,
                detail=str(error),
                source=RuntimeEvidenceSource.SUPERVISOR,
            ),
        ),
    )


def _format_number(value: float) -> str:
    return f"{value:g}"


def _local_docker_endpoint() -> str:
    if os.name == "nt":
        return "npipe:////./pipe/docker_engine"
    return "unix:///var/run/docker.sock"


def _trusted_docker_config_directory() -> Path:
    directory = Path(__file__).with_name("docker_cli_config")
    config = directory / "config.json"
    try:
        directory_metadata = directory.lstat()
        config_metadata = config.lstat()
        children = tuple(item.name for item in directory.iterdir())
        content = config.read_bytes()
    except OSError as error:
        raise ExecutionPolicyError(
            "trusted empty Docker CLI configuration is unavailable"
        ) from error
    if (
        _is_link_or_reparse(directory, directory_metadata)
        or _is_link_or_reparse(config, config_metadata)
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or not stat.S_ISREG(config_metadata.st_mode)
        or children != ("config.json",)
        or content.strip() != b"{}"
    ):
        raise ExecutionPolicyError(
            "trusted Docker CLI configuration must contain only an empty config.json"
        )
    return directory.resolve(strict=True)


def _verify_image_has_no_declared_volumes(
    resolved_binary: Path,
    image: str,
    *,
    timeout_seconds: int,
) -> None:
    """Fail closed when image metadata can create an untracked writable volume."""

    command = (
        str(resolved_binary),
        "--config",
        str(_trusted_docker_config_directory()),
        "--host",
        _local_docker_endpoint(),
        "image",
        "inspect",
        "--platform",
        _DOCKER_PLATFORM,
        "--format",
        "{{if .Config.Volumes}}declared{{else}}none{{end}}",
        image,
    )
    try:
        completed = subprocess.run(
            command,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
            cwd=str(resolved_binary.parent),
            env=_docker_cli_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ExecutionPolicyError(
            f"container image metadata could not be verified: {error}"
        ) from error
    output = (completed.stdout or b"")[:64].decode("ascii", errors="replace").strip()
    if completed.returncode != 0 or output not in {"none", "declared"}:
        raise ExecutionPolicyError(
            "container image metadata could not be verified with the local Docker daemon"
        )
    if output == "declared":
        raise ExecutionPolicyError(
            "container image declares a VOLUME that would create an untracked writable mount"
        )


def _ambient_docker_routing_variables() -> tuple[str, ...]:
    return tuple(
        sorted(
            name
            for name, value in os.environ.items()
            if name.upper() in _DOCKER_ROUTING_ENVIRONMENT and value
        )
    )


def _docker_cli_environment() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if name.upper() in _DOCKER_CLI_ENVIRONMENT_ALLOWLIST
    }


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


def _resolve_docker_binary(
    requested: str,
    *,
    forbidden: tuple[Path, ...],
) -> Path | None:
    """Resolve Docker without consulting an untrusted working directory."""

    forbidden_roots: list[Path] = []
    for item in forbidden:
        try:
            forbidden_roots.append(item.resolve(strict=False))
        except (OSError, RuntimeError):
            continue

    candidate = Path(requested)
    if candidate.is_absolute():
        located: str | None = str(candidate)
    else:
        if candidate.name != requested or candidate.name.lower() not in {
            "docker",
            "docker.exe",
        }:
            return None
        safe_entries: list[str] = []
        for raw_entry in os.environ.get("PATH", "").split(os.pathsep):
            if not raw_entry:
                continue
            entry = Path(raw_entry)
            if not entry.is_absolute():
                continue
            try:
                resolved_entry = entry.resolve(strict=False)
            except (OSError, RuntimeError):
                continue
            if any(
                resolved_entry == root or resolved_entry.is_relative_to(root)
                for root in forbidden_roots
            ):
                continue
            safe_entries.append(str(resolved_entry))
        located = shutil.which(requested, path=os.pathsep.join(safe_entries))
        if located is None:
            return None

    try:
        resolved = Path(located).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not resolved.is_file():
        return None
    if os.name == "nt" and resolved.suffix.lower() != ".exe":
        return None
    if any(
        resolved == root or resolved.is_relative_to(root)
        for root in forbidden_roots
    ):
        return None
    return resolved


def _container_user_arguments() -> tuple[str, ...]:
    uid, gid = _container_identity()
    return ("--user", f"{uid}:{gid}")


def _container_identity() -> tuple[int, int]:
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if callable(getuid) and callable(getgid):
        uid, gid = int(getuid()), int(getgid())
        if uid > 0:
            return uid, gid
    # Docker Desktop still runs a Linux container even when the host Python is
    # Windows-native.  Fail closed to the conventional unprivileged nobody
    # identity rather than silently running the research process as root.
    return 65534, 65534


def _require_runtime_output_access(output: Path) -> None:
    if os.name != "posix":
        return
    uid, gid = _container_identity()
    metadata = output.stat(follow_symlinks=False)
    if uid == metadata.st_uid:
        permissions = (metadata.st_mode >> 6) & 0o7
    elif gid == metadata.st_gid:
        permissions = (metadata.st_mode >> 3) & 0o7
    else:
        permissions = metadata.st_mode & 0o7
    if permissions & 0o7 != 0o7:
        raise ExecutionPolicyError(
            "output directory is not readable, writable, and searchable by "
            f"sandbox uid/gid {uid}:{gid}"
        )


def _is_python_execution(argv: tuple[str, ...]) -> bool:
    if not argv:
        return False
    executable = Path(argv[0]).name.lower()
    return bool(re.fullmatch(r"python(?:3(?:\.\d+)?)?(?:\.exe)?", executable))


def _python_audit_directory() -> Path:
    directory = Path(__file__).with_name("python_audit").resolve(strict=True)
    if not (directory / "sitecustomize.py").is_file():
        raise ExecutionPolicyError("bundled Python audit hook is unavailable")
    return directory


def _audit_log_container_path(run_id: str) -> str:
    if not re.fullmatch(r"r-sandbox-[a-z0-9-]{1,64}", run_id):
        raise ExecutionPolicyError("invalid internal sandbox run id")
    return f"/output/.r-sandbox/events-{run_id}.jsonl"


def _audit_event_file(output: Path, run_id: str) -> Path:
    _audit_log_container_path(run_id)
    return output / ".r-sandbox" / f"events-{run_id}.jsonl"


def _prepare_python_audit_log(output: Path, run_id: str) -> Path:
    event_file = _audit_event_file(output, run_id)
    event_directory = event_file.parent
    created = False
    try:
        event_directory.mkdir(mode=0o700, exist_ok=False)
        created = True
    except FileExistsError:
        pass
    except OSError as error:
        raise ExecutionPolicyError(
            f"Python audit directory could not be prepared safely: {error}"
        ) from error
    try:
        metadata = event_directory.lstat()
    except OSError as error:
        raise ExecutionPolicyError(
            f"Python audit directory could not be prepared safely: {error}"
        ) from error
    if _is_link_or_reparse(event_directory, metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ExecutionPolicyError(
            "Python audit directory must not be a link, junction, or reparse point"
        )
    try:
        event_directory.resolve(strict=True).relative_to(output.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as error:
        raise ExecutionPolicyError(
            "Python audit directory resolved outside the designated output"
        ) from error
    if os.name == "posix":
        uid, gid = _container_identity()
        try:
            if created and int(os.getuid()) == 0:
                os.chown(event_directory, uid, gid, follow_symlinks=False)
                os.chmod(event_directory, 0o700, follow_symlinks=False)
            _require_runtime_output_access(event_directory)
        except OSError as error:
            raise ExecutionPolicyError(
                "Python audit directory is not writable by the sandbox user"
            ) from error
    try:
        event_file.lstat()
    except FileNotFoundError:
        return event_file
    except OSError as error:
        raise ExecutionPolicyError(
            f"Python audit event path could not be checked safely: {error}"
        ) from error
    raise ExecutionPolicyError("A supposedly unique Python audit event path already exists")


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
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _load_python_audit_events(
    output: Path,
    *,
    run_id: str,
    max_bytes: int = 2 * 1024 * 1024,
    max_events: int = 10_000,
) -> tuple[RuntimeEvent, ...]:
    event_file = _audit_event_file(output, run_id)
    try:
        directory_metadata = event_file.parent.lstat()
        if _is_link_or_reparse(event_file.parent, directory_metadata):
            raise OSError("audit directory is a link, junction, or reparse point")
        event_file.parent.resolve(strict=True).relative_to(output.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as error:
        return (
            RuntimeEvent(
                event_type="observer",
                action="audit",
                target=str(event_file.parent),
                allowed=False,
                detail=f"Python audit directory failed containment validation: {error}",
                source=RuntimeEvidenceSource.SUPERVISOR,
            ),
        )
    try:
        metadata = event_file.lstat()
    except FileNotFoundError:
        return (
            RuntimeEvent(
                event_type="observer",
                action="audit",
                target="python",
                allowed=False,
                detail=(
                    "Python audit hook produced no event log; site initialization "
                    "may have been bypassed."
                ),
                source=RuntimeEvidenceSource.SUPERVISOR,
            ),
        )
    if (
        _is_link_or_reparse(event_file, metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > max_bytes
    ):
        return (
            RuntimeEvent(
                event_type="observer",
                action="audit",
                target=str(event_file),
                allowed=False,
                detail="Python audit event log was not a bounded regular file.",
                source=RuntimeEvidenceSource.SUPERVISOR,
            ),
        )

    events: list[RuntimeEvent] = []
    invalid_records = 0
    audit_hook_seen = False
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(event_file, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8", errors="replace") as stream:
            for index, line in enumerate(stream):
                if index >= max_events:
                    events.append(
                        RuntimeEvent(
                            event_type="observer",
                            action="truncate",
                            target=str(event_file),
                            allowed=False,
                            detail=f"Audit events were truncated at {max_events} records.",
                            source=RuntimeEvidenceSource.SUPERVISOR,
                        )
                    )
                    break
                try:
                    payload = json.loads(line)
                except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
                    invalid_records += 1
                    continue
                if not isinstance(payload, dict):
                    invalid_records += 1
                    continue
                if payload.get("run_id") != run_id:
                    invalid_records += 1
                    continue
                allowed = payload.get("allowed")
                if not isinstance(allowed, bool):
                    invalid_records += 1
                    continue
                event = RuntimeEvent(
                    event_type=_bounded_field(payload.get("event_type"), "audit"),
                    action=_bounded_field(payload.get("action"), "attempt"),
                    target=_bounded_field(payload.get("target"), "unknown", limit=500),
                    allowed=allowed,
                    detail=(
                        "[python-audit, target-controlled telemetry] "
                        + _bounded_field(payload.get("detail"), "", limit=500)
                    ).rstrip(),
                )
                events.append(event)
                audit_hook_seen = audit_hook_seen or (
                    event.event_type == "runtime"
                    and event.action == "audit_hook"
                    and event.target == "python"
                    and event.allowed
                )
    except OSError as error:
        return (
            RuntimeEvent(
                event_type="observer",
                action="audit",
                target=str(event_file),
                allowed=False,
                detail=f"Python audit event log could not be read safely: {error}",
                source=RuntimeEvidenceSource.SUPERVISOR,
            ),
        )
    if invalid_records:
        events.append(
            RuntimeEvent(
                event_type="observer",
                action="validate",
                target=str(event_file),
                allowed=False,
                detail=f"Audit log contained {invalid_records} invalid record(s).",
                source=RuntimeEvidenceSource.SUPERVISOR,
            )
        )
    if not audit_hook_seen:
        events.append(
            RuntimeEvent(
                event_type="observer",
                action="handshake",
                target="python",
                allowed=False,
                detail="Required Python audit-hook installation event was absent.",
                source=RuntimeEvidenceSource.SUPERVISOR,
            )
        )
    return tuple(events)


def _bounded_field(value: object, default: str, *, limit: int = 100) -> str:
    if not isinstance(value, str) or not value:
        return default
    value = value.replace("\x00", "").replace("\r", " ").replace("\n", " ")
    return value[:limit]


def _truncate(value: str, limit: int) -> str:
    if limit <= 0:
        return ""
    if len(value) <= limit:
        return value
    marker = f"\n...[truncated {len(value) - limit} characters]...\n"
    available = max(0, limit - len(marker))
    head = available // 2
    tail = available - head
    return value[:head] + marker + (value[-tail:] if tail else "")
