from __future__ import annotations

from dataclasses import replace
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from r_sandbox.models import (
    AgentOutcome,
    ExecutionResult,
    ResourceLimits,
    RuntimeEvent,
    SandboxSpec,
)
from r_sandbox.tools.execution_supervisor import (
    DockerExecutionSupervisor,
    DryRunExecutionSupervisor,
)
from r_sandbox.tools.execution_supervisor import supervisor as supervisor_module
from r_sandbox.tools.runtime_observer import (
    ManifestLimitExceeded,
    RuntimeObserver,
    capture_output_manifest,
)


class _TrackingStream(io.BytesIO):
    def __init__(self, value: bytes) -> None:
        super().__init__(value)
        self.close_requested = False

    def close(self) -> None:
        self.close_requested = True


class _FinishedProcess:
    def __init__(self, stdout: bytes, stderr: bytes, returncode: int = 0) -> None:
        self.stdout = _TrackingStream(stdout)
        self.stderr = _TrackingStream(stderr)
        self.returncode = returncode

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def poll(self) -> int:
        return self.returncode


class _TimedOutProcess:
    def __init__(self, stdout: bytes, stderr: bytes) -> None:
        self.stdout = _TrackingStream(stdout)
        self.stderr = _TrackingStream(stderr)
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired("docker", timeout)
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


class _RunningProcess:
    def __init__(self, on_wait=None) -> None:
        self.stdout = _TrackingStream(b"")
        self.stderr = _TrackingStream(b"")
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False
        self._on_wait = on_wait
        self._wait_started = False
        self._stopped = threading.Event()
        self._lock = threading.Lock()

    def wait(self, timeout: float | None = None) -> int:
        with self._lock:
            if not self._wait_started:
                self._wait_started = True
                if self._on_wait is not None:
                    self._on_wait()
        if not self._stopped.wait(timeout):
            raise subprocess.TimeoutExpired("docker", timeout)
        assert self.returncode is not None
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15
        self._stopped.set()

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self._stopped.set()


class _WaitErrorProcess(_RunningProcess):
    def wait(self, timeout: float | None = None) -> int:
        raise RuntimeError("simulated wait failure")


class _UnlimitedPids(int):
    def __str__(self) -> str:
        return "-1"


class _PhantomDevices(tuple):
    def __iter__(self):
        return iter(())


def _docker_cleanup_success(command, **_kwargs):
    if len(command) > 5 and command[5] == "create":
        stdout = (b"a" * 64) + b"\n"
    elif "container" in command and "ls" in command:
        stdout = b""
    else:
        stdout = None
    return subprocess.CompletedProcess(command, 0, stdout=stdout)


def _sandbox_spec(root: Path) -> SandboxSpec:
    repository = root / "repository"
    output = root / "output"
    repository.mkdir()
    output.mkdir()
    (repository / "experiment.py").write_text("print('fixture')\n", encoding="utf-8")
    if os.name == "posix":
        uid, gid = supervisor_module._container_identity()
        if os.getuid() == 0:
            os.chown(output, uid, gid)
        os.chmod(output, 0o700)
    return SandboxSpec(
        repository=str(repository.resolve()),
        output=str(output.resolve()),
        image="python:3.11-slim",
        argv=("python", "experiment.py"),
        limits=ResourceLimits(timeout_seconds=1),
    )


class DockerStreamingTests(unittest.TestCase):
    def test_interrupt_between_create_and_supervision_cleans_exact_container_id(self) -> None:
        resolved_docker = Path(sys.executable).resolve()
        supervisor = DockerExecutionSupervisor()
        container_id = "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            with (
                patch.object(
                    supervisor_module,
                    "_resolve_docker_binary",
                    return_value=resolved_docker,
                ),
                patch.object(supervisor_module, "_verify_image_has_no_declared_volumes"),
                patch.object(
                    supervisor_module.subprocess,
                    "run",
                    side_effect=_docker_cleanup_success,
                ),
                patch.object(
                    supervisor_module.subprocess,
                    "Popen",
                    side_effect=KeyboardInterrupt,
                ),
                patch.object(
                    DockerExecutionSupervisor,
                    "_remove_named_container",
                    return_value=supervisor_module._ContainerCleanup(
                        "absence confirmed",
                        True,
                    ),
                ) as cleanup,
                self.assertRaises(KeyboardInterrupt),
            ):
                supervisor.execute(spec)
        cleanup.assert_called_once_with(container_id, resolved_docker)

    def test_create_name_collision_never_deletes_an_unowned_container(self) -> None:
        resolved_docker = Path(sys.executable).resolve()
        supervisor = DockerExecutionSupervisor()
        creation_failed = subprocess.CompletedProcess((), 1, stdout=b"")
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            with (
                patch.object(supervisor_module, "_resolve_docker_binary", return_value=resolved_docker),
                patch.object(supervisor_module, "_verify_image_has_no_declared_volumes"),
                patch.object(supervisor_module.subprocess, "run", return_value=creation_failed),
                patch.object(supervisor_module.subprocess, "Popen") as popen,
                patch.object(DockerExecutionSupervisor, "_remove_named_container") as cleanup,
            ):
                result = supervisor.execute(spec)
        self.assertEqual(result.status, AgentOutcome.FAILED)
        popen.assert_not_called()
        cleanup.assert_not_called()

    def test_post_launch_wait_error_terminates_client_before_container_cleanup(self) -> None:
        process = _WaitErrorProcess()
        resolved_docker = Path(sys.executable).resolve()
        order: list[str] = []
        supervisor = DockerExecutionSupervisor()

        def terminate(candidate):
            order.append("terminate-client")
            candidate.terminate()
            return "Docker client terminated."

        def cleanup(*_args):
            order.append("remove-container")
            return supervisor_module._ContainerCleanup("absent", True)

        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            with (
                patch.object(supervisor_module, "_resolve_docker_binary", return_value=resolved_docker),
                patch.object(supervisor_module, "_verify_image_has_no_declared_volumes"),
                patch.object(supervisor_module.subprocess, "run", side_effect=_docker_cleanup_success),
                patch.object(supervisor_module.subprocess, "Popen", return_value=process),
                patch.object(supervisor_module, "_terminate_docker_client", side_effect=terminate),
                patch.object(DockerExecutionSupervisor, "_remove_named_container", side_effect=cleanup),
            ):
                result = supervisor.execute(spec)
        self.assertEqual(result.status, AgentOutcome.FAILED)
        self.assertEqual(order[:2], ["terminate-client", "remove-container"])
        self.assertTrue(process.terminated)

    def test_unexpected_output_monitor_exception_fails_closed(self) -> None:
        process = _RunningProcess()
        resolved_docker = Path(sys.executable).resolve()
        supervisor = DockerExecutionSupervisor(output_poll_interval_seconds=0.01)
        with tempfile.TemporaryDirectory() as directory:
            spec = replace(_sandbox_spec(Path(directory)), limits=ResourceLimits(timeout_seconds=5))
            with (
                patch.object(supervisor_module, "_resolve_docker_binary", return_value=resolved_docker),
                patch.object(supervisor_module, "_verify_image_has_no_declared_volumes"),
                patch.object(supervisor_module, "_check_output_budget", side_effect=(None, AssertionError("boom"))),
                patch.object(supervisor_module.subprocess, "run", side_effect=_docker_cleanup_success),
                patch.object(supervisor_module.subprocess, "Popen", return_value=process),
                patch.object(
                    DockerExecutionSupervisor,
                    "_remove_named_container",
                    return_value=supervisor_module._ContainerCleanup("absent", True),
                ),
            ):
                result = supervisor.execute(spec)
        self.assertEqual(result.status, AgentOutcome.FAILED)
        self.assertTrue(process.terminated)
        self.assertTrue(
            any(event.action == "output_scan" and not event.allowed for event in result.events)
        )

    def test_unconfirmed_container_teardown_is_a_structured_failure(self) -> None:
        process = _FinishedProcess(b"", b"")
        resolved_docker = Path(sys.executable).resolve()
        supervisor = DockerExecutionSupervisor()
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            with (
                patch.object(supervisor_module, "_resolve_docker_binary", return_value=resolved_docker),
                patch.object(supervisor_module, "_verify_image_has_no_declared_volumes"),
                patch.object(supervisor_module, "_load_python_audit_events", return_value=()),
                patch.object(supervisor_module.subprocess, "run", side_effect=_docker_cleanup_success),
                patch.object(supervisor_module.subprocess, "Popen", return_value=process),
                patch.object(
                    DockerExecutionSupervisor,
                    "_remove_named_container",
                    return_value=supervisor_module._ContainerCleanup("teardown unconfirmed", False),
                ),
            ):
                result = supervisor.execute(spec)
        self.assertEqual(result.status, AgentOutcome.FAILED)
        self.assertIsNone(result.exit_code)
        self.assertTrue(
            any(event.action == "container_teardown" for event in result.events)
        )

    def test_output_limit_event_omits_target_controlled_filename(self) -> None:
        canary = "ZZ_LEAKTOKEN"
        with tempfile.TemporaryDirectory() as directory:
            spec = replace(
                _sandbox_spec(Path(directory)),
                limits=ResourceLimits(output_files=1),
            )
            output = Path(spec.output)
            (output / "a.txt").write_text("a", encoding="utf-8")
            (output / f"{canary}.txt").write_text("b", encoding="utf-8")
            failure = supervisor_module._check_output_budget(output, spec)
        self.assertIsNotNone(failure)
        self.assertNotIn(canary, failure.event.target)
        self.assertNotIn(canary, failure.event.detail)
    def test_sandbox_contract_rejects_primitive_and_tuple_subclasses(self) -> None:
        with self.assertRaisesRegex(TypeError, "cpus"):
            ResourceLimits(cpus=10**1000)
        with self.assertRaisesRegex(TypeError, "pids"):
            ResourceLimits(pids=_UnlimitedPids(128))
        with self.assertRaisesRegex(TypeError, "duration"):
            ExecutionResult(
                status=AgentOutcome.FAILED,
                exit_code=1,
                duration_seconds=10**1000,
            )
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            with self.assertRaisesRegex(TypeError, "devices"):
                replace(spec, devices=_PhantomDevices(("not-approved",)))

    def test_huge_poll_interval_is_rejected_without_numeric_overflow(self) -> None:
        with self.assertRaisesRegex(TypeError, "output_poll_interval_seconds"):
            DockerExecutionSupervisor(output_poll_interval_seconds=10**1000)

    def test_supervisor_resnapshots_a_tampered_frozen_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            object.__setattr__(
                spec,
                "devices",
                _PhantomDevices(("not-approved",)),
            )
            result = DryRunExecutionSupervisor().execute(spec)
        self.assertEqual(result.status, AgentOutcome.BLOCKED)
        self.assertNotIn("--gpus", result.command_preview)
    def test_custom_environment_is_rejected_instead_of_inheriting_host_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = replace(
                _sandbox_spec(Path(directory)),
                environment=(("AWS_SECRET_ACCESS_KEY", "explicit-placeholder"),),
            )
            with patch.dict(
                os.environ,
                {"AWS_SECRET_ACCESS_KEY": "real-host-secret"},
            ):
                result = DryRunExecutionSupervisor().execute(spec)
        self.assertEqual(result.status, AgentOutcome.BLOCKED)
        self.assertIn("environment forwarding", result.stderr)
        self.assertNotIn("real-host-secret", " ".join(result.command_preview))

    def test_python_bootstrap_prevents_repository_sitecustomize_shadowing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            (Path(spec.repository) / "sitecustomize.py").write_text(
                "raise RuntimeError('untrusted startup hook')\n",
                encoding="utf-8",
            )
            command = DryRunExecutionSupervisor().execute(spec).command_preview
        image_index = command.index(spec.image)
        self.assertEqual(command[image_index + 1], "-P")
        self.assertEqual(command[image_index + 2], "experiment.py")
        self.assertIn("PYTHONPATH=/opt/r-sandbox-audit", command)
        self.assertIn("PYTHONSAFEPATH=1", command)
        self.assertIn("PYTHONNOUSERSITE=1", command)

    def test_direct_supervisor_rejects_prefixed_python_bypass_flags(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            for argv in (
                ("python", "-B", "-S", "experiment.py"),
                ("python", "-B", "-c", "print('bypass')"),
            ):
                with self.subTest(argv=argv):
                    result = DryRunExecutionSupervisor().execute(
                        replace(spec, argv=argv)
                    )
                    self.assertEqual(result.status, AgentOutcome.BLOCKED)
                    self.assertIn("interpreter flags", result.stderr)

    def test_direct_supervisor_requires_entrypoint_inside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            output_script = Path(spec.output) / "preexisting.py"
            output_script.write_text("print('writable code')\n", encoding="utf-8")
            for argv in (
                ("python", "/output/preexisting.py"),
                ("python", "../outside.py"),
                ("python", "-m", "pip"),
            ):
                with self.subTest(argv=argv):
                    result = DryRunExecutionSupervisor().execute(
                        replace(spec, argv=argv)
                    )
                    self.assertEqual(result.status, AgentOutcome.BLOCKED)
                    self.assertIn("entrypoint", result.stderr)

    def test_internal_audit_run_id_cannot_be_overridden_by_spec(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = replace(
                _sandbox_spec(Path(directory)),
                environment=(("R_SANDBOX_RUN_ID", "attacker-controlled"),),
            )
            result = DryRunExecutionSupervisor().execute(spec)
        self.assertEqual(result.status, AgentOutcome.BLOCKED)
        self.assertIn("reserved", result.stderr)

    def test_docker_binary_in_untrusted_repository_is_never_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            executable = repository / ("docker.exe" if os.name == "nt" else "docker")
            executable.write_bytes(b"not a trusted runtime")
            if os.name != "nt":
                executable.chmod(0o755)
            with patch.dict(os.environ, {"PATH": str(repository)}):
                resolved = supervisor_module._resolve_docker_binary(
                    "docker",
                    forbidden=(repository,),
                )
        self.assertIsNone(resolved)

    def test_stdout_and_stderr_are_fully_drained_with_bounded_head_tail(self) -> None:
        stdout = b"HEAD" + (b"x" * 100) + b"TAIL"
        stderr = b"ERR-HEAD" + (b"y" * 100) + b"ERR-TAIL"
        process = _FinishedProcess(stdout, stderr)
        resolved_docker = Path(sys.executable).resolve()

        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            with (
                patch.object(
                    supervisor_module,
                    "_resolve_docker_binary",
                    return_value=resolved_docker,
                ),
                patch.object(
                    supervisor_module,
                    "_load_python_audit_events",
                    return_value=(),
                ),
                patch.object(
                    supervisor_module,
                    "_verify_image_has_no_declared_volumes",
                ),
                patch.object(
                    supervisor_module.subprocess,
                    "Popen",
                    return_value=process,
                ) as popen,
                patch.object(
                    supervisor_module.subprocess,
                    "run",
                    side_effect=_docker_cleanup_success,
                ),
            ):
                result = DockerExecutionSupervisor(max_output_chars=16).execute(spec)

        self.assertEqual(result.status, AgentOutcome.SUCCEEDED)
        self.assertEqual(process.stdout.tell(), len(stdout))
        self.assertEqual(process.stderr.tell(), len(stderr))
        self.assertTrue(process.stdout.close_requested)
        self.assertTrue(process.stderr.close_requested)
        self.assertTrue(result.stdout.startswith("HEAD"))
        self.assertTrue(result.stdout.endswith("TAIL"))
        self.assertIn("truncated 92 bytes", result.stdout)
        self.assertTrue(result.stderr.startswith("ERR-"))
        self.assertTrue(result.stderr.endswith("TAIL"))

        _args, kwargs = popen.call_args
        self.assertEqual(_args[0][5], "start")
        self.assertEqual(_args[0][-1], "a" * 64)
        self.assertEqual(result.command_preview[5], "create")
        self.assertNotIn("--rm", result.command_preview)
        self.assertNotIn("capture_output", kwargs)
        self.assertNotIn("text", kwargs)
        self.assertNotIn("encoding", kwargs)
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(kwargs["stderr"], subprocess.PIPE)
        self.assertFalse(kwargs["shell"])

    def test_target_stderr_cannot_spoof_runtime_unavailable(self) -> None:
        process = _FinishedProcess(
            b"",
            b"cannot connect to the docker daemon",
            returncode=7,
        )
        resolved_docker = Path(sys.executable).resolve()
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            with (
                patch.object(
                    supervisor_module,
                    "_resolve_docker_binary",
                    return_value=resolved_docker,
                ),
                patch.object(
                    supervisor_module,
                    "_verify_image_has_no_declared_volumes",
                ),
                patch.object(
                    supervisor_module,
                    "_load_python_audit_events",
                    return_value=(),
                ),
                patch.object(
                    supervisor_module.subprocess,
                    "Popen",
                    return_value=process,
                ),
                patch.object(
                    supervisor_module.subprocess,
                    "run",
                    side_effect=_docker_cleanup_success,
                ),
            ):
                result = DockerExecutionSupervisor().execute(spec)
        self.assertEqual(result.status, AgentOutcome.FAILED)
        self.assertEqual(result.events[-1].target, "python")
        self.assertEqual(RuntimeObserver().inspect(result).classification, "unknown_failure")

    def test_timeout_cleanup_uses_resolved_binary_and_exact_generated_name(self) -> None:
        process = _TimedOutProcess(b"a" * 100, b"b" * 100)
        resolved_docker = Path(sys.executable).resolve()
        prior_audit_event = RuntimeEvent(
            "secret",
            "read",
            "env:CANARY",
            False,
            "[python-audit, target-controlled telemetry] blocked",
        )

        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            with (
                patch.object(
                    supervisor_module,
                    "_resolve_docker_binary",
                    return_value=resolved_docker,
                ),
                patch.object(
                    supervisor_module.uuid,
                    "uuid4",
                    return_value=SimpleNamespace(hex="0123456789abcdef"),
                ),
                patch.object(
                    supervisor_module,
                    "_verify_image_has_no_declared_volumes",
                ),
                patch.object(
                    supervisor_module,
                    "_load_python_audit_events",
                    return_value=(prior_audit_event,),
                ),
                patch.object(
                    supervisor_module.subprocess,
                    "Popen",
                    return_value=process,
                ),
                patch.object(
                    supervisor_module.subprocess,
                    "run",
                    side_effect=_docker_cleanup_success,
                ) as cleanup,
            ):
                result = DockerExecutionSupervisor(max_output_chars=16).execute(spec)

        self.assertEqual(result.status, AgentOutcome.FAILED)
        self.assertIsNone(result.exit_code)
        self.assertTrue(process.terminated)
        self.assertFalse(process.killed)
        self.assertIn("timeout", result.stderr.lower())
        self.assertIn(prior_audit_event, result.events)
        self.assertEqual(process.stdout.tell(), 100)
        self.assertEqual(process.stderr.tell(), 100)

        cleanup_call = next(
            call for call in cleanup.call_args_list if "rm" in call.args[0]
        )
        cleanup_command = cleanup_call.args[0]
        self.assertEqual(
            cleanup_command,
            (
                str(resolved_docker),
                "--config",
                str(supervisor_module._trusted_docker_config_directory()),
                "--host",
                supervisor_module._local_docker_endpoint(),
                "rm",
                "--force",
                "a" * 64,
            ),
        )
        self.assertTrue(Path(cleanup_command[0]).is_absolute())
        self.assertFalse(cleanup.call_args.kwargs["shell"])
        first_cleanup = cleanup_call
        self.assertEqual(first_cleanup.kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(first_cleanup.kwargs["stderr"], subprocess.DEVNULL)
        self.assertNotIn("DOCKER_HOST", first_cleanup.kwargs["env"])
        self.assertNotIn("DOCKER_CONTEXT", first_cleanup.kwargs["env"])

    def test_ambient_remote_docker_route_is_blocked_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            with (
                patch.dict(
                    os.environ,
                    {"DOCKER_HOST": "tcp://remote.example.invalid:2376"},
                ),
                patch.object(supervisor_module.subprocess, "Popen") as popen,
            ):
                result = DockerExecutionSupervisor().execute(spec)

        self.assertEqual(result.status, AgentOutcome.BLOCKED)
        self.assertIn("DOCKER_HOST", result.stderr)
        popen.assert_not_called()

    def test_runtime_output_file_limit_stops_exact_named_container(self) -> None:
        resolved_docker = Path(sys.executable).resolve()
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            output = Path(spec.output)

            def exceed_limit() -> None:
                (output / "one.txt").write_text("1", encoding="utf-8")
                (output / "two.txt").write_text("2", encoding="utf-8")

            process = _RunningProcess(exceed_limit)
            spec = replace(
                spec,
                limits=replace(
                    spec.limits,
                    output_files=1,
                    timeout_seconds=5,
                ),
            )
            with (
                patch.object(
                    supervisor_module,
                    "_resolve_docker_binary",
                    return_value=resolved_docker,
                ),
                patch.object(
                    supervisor_module.uuid,
                    "uuid4",
                    return_value=SimpleNamespace(hex="feedfacecafebeef"),
                ),
                patch.object(
                    supervisor_module,
                    "_verify_image_has_no_declared_volumes",
                ),
                patch.object(
                    supervisor_module.subprocess,
                    "Popen",
                    return_value=process,
                ),
                patch.object(
                    supervisor_module.subprocess,
                    "run",
                    side_effect=_docker_cleanup_success,
                ) as cleanup,
            ):
                result = DockerExecutionSupervisor(
                    output_poll_interval_seconds=0.01
                ).execute(spec)

        self.assertEqual(result.status, AgentOutcome.FAILED)
        self.assertTrue(process.terminated)
        self.assertTrue(
            any(
                event.event_type == "resource"
                and event.target == "output_files"
                and not event.allowed
                for event in result.events
            )
        )
        self.assertEqual(
            next(call for call in cleanup.call_args_list if "rm" in call.args[0]).args[0],
            (
                str(resolved_docker),
                "--config",
                str(supervisor_module._trusted_docker_config_directory()),
                "--host",
                supervisor_module._local_docker_endpoint(),
                "rm",
                "--force",
                "a" * 64,
            ),
        )

    def test_runtime_output_scan_failure_stops_sandbox_and_reports_observer(self) -> None:
        resolved_docker = Path(sys.executable).resolve()
        prior_audit_event = RuntimeEvent(
            "network",
            "connect",
            "collector.example.org:443",
            False,
            "[python-audit, target-controlled telemetry] blocked",
        )
        with tempfile.TemporaryDirectory() as directory:
            spec = replace(
                _sandbox_spec(Path(directory)),
                limits=ResourceLimits(timeout_seconds=5),
            )
            baseline = capture_output_manifest(Path(spec.output))
            process = _RunningProcess()
            with (
                patch.object(
                    supervisor_module,
                    "_resolve_docker_binary",
                    return_value=resolved_docker,
                ),
                patch.object(
                    supervisor_module,
                    "capture_output_manifest",
                    side_effect=(baseline, OSError("simulated scan failure")),
                ),
                patch.object(
                    supervisor_module,
                    "_verify_image_has_no_declared_volumes",
                ),
                patch.object(
                    supervisor_module,
                    "_load_python_audit_events",
                    return_value=(prior_audit_event,),
                ),
                patch.object(
                    supervisor_module.subprocess,
                    "Popen",
                    return_value=process,
                ),
                patch.object(
                    supervisor_module.subprocess,
                    "run",
                    side_effect=_docker_cleanup_success,
                ) as cleanup,
            ):
                result = DockerExecutionSupervisor(
                    output_poll_interval_seconds=0.01
                ).execute(spec)

        self.assertEqual(result.status, AgentOutcome.FAILED)
        self.assertTrue(process.terminated)
        self.assertEqual(cleanup.call_count, 5)
        self.assertIn(prior_audit_event, result.events)
        self.assertTrue(
            any(
                event.event_type == "observer"
                and event.action == "output_scan"
                and not event.allowed
                for event in result.events
            )
        )

    def test_docker_command_disables_implicit_writable_and_disk_channels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            command = DryRunExecutionSupervisor().execute(spec).command_preview
        self.assertIn("--no-healthcheck", command)
        self.assertEqual(command[command.index("--platform") + 1], "linux/amd64")
        self.assertEqual(command[command.index("--log-driver") + 1], "none")
        self.assertEqual(
            command[command.index("--memory-swap") + 1],
            f"{spec.limits.memory_mb}m",
        )
        self.assertEqual(command[command.index("--memory-swappiness") + 1], "0")
        self.assertEqual(
            command[command.index("--shm-size") + 1],
            f"{spec.limits.shared_memory_mb}m",
        )
        self.assertEqual(command[command.index("--ulimit") + 1], "core=0:0")
        self.assertIn(
            f"size={spec.limits.temporary_mb}m",
            command[command.index("--tmpfs") + 1],
        )
        self.assertEqual(
            Path(command[command.index("--config") + 1]),
            supervisor_module._trusted_docker_config_directory(),
        )

    def test_unapproved_gpu_cannot_arrive_through_default_runtime_or_image_env(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = _sandbox_spec(Path(directory))
            command = DryRunExecutionSupervisor().execute(spec).command_preview
        self.assertEqual(command[command.index("--runtime") + 1], "runc")
        env_values = tuple(
            command[index + 1]
            for index, item in enumerate(command[:-1])
            if item == "--env"
        )
        self.assertIn("NVIDIA_VISIBLE_DEVICES=void", env_values)
        self.assertIn("NVIDIA_DRIVER_CAPABILITIES=", env_values)
        self.assertIn("CUDA_VISIBLE_DEVICES=", env_values)
        self.assertNotIn("--gpus", command)

    def test_approved_gpu_is_still_an_explicit_device_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = replace(_sandbox_spec(Path(directory)), devices=("gpu",))
            command = DryRunExecutionSupervisor().execute(spec).command_preview
        self.assertEqual(command[command.index("--gpus") + 1], "all")
        self.assertNotIn("--runtime", command)

    def test_docker_cli_environment_is_a_small_allowlist(self) -> None:
        environment = {
            "SYSTEMROOT": "C:/Windows",
            "TEMP": "C:/Temp",
            "DOCKER_DEFAULT_PLATFORM": "linux/arm64",
            "DOCKER_API_VERSION": "1.20",
            "HTTP_PROXY": "http://secret@proxy",
            "AWS_SECRET_ACCESS_KEY": "secret",
        }
        with patch.dict(os.environ, environment, clear=True):
            child = supervisor_module._docker_cli_environment()
        self.assertEqual(
            child,
            {"SYSTEMROOT": "C:/Windows", "TEMP": "C:/Temp"},
        )

    def test_image_declared_volume_is_rejected(self) -> None:
        completed = subprocess.CompletedProcess((), 0, stdout=b"declared\n")
        with patch.object(
            supervisor_module.subprocess,
            "run",
            return_value=completed,
        ):
            with self.assertRaises(supervisor_module.ExecutionPolicyError):
                supervisor_module._verify_image_has_no_declared_volumes(
                    Path(sys.executable).resolve(),
                    "python:3.11-slim",
                    timeout_seconds=1,
                )

    def test_trusted_empty_docker_config_overrides_host_home_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake_home = base / "home"
            host_config = fake_home / ".docker"
            host_config.mkdir(parents=True)
            (host_config / "config.json").write_text(
                '{"proxies":{"default":{"httpProxy":"http://host-secret@proxy"}}}',
                encoding="utf-8",
            )
            spec_root = base / "spec"
            spec_root.mkdir()
            spec = _sandbox_spec(spec_root)
            with patch.dict(os.environ, {"HOME": str(fake_home)}):
                command = DryRunExecutionSupervisor().execute(spec).command_preview
        config_path = Path(command[command.index("--config") + 1])
        self.assertEqual(config_path, supervisor_module._trusted_docker_config_directory())
        self.assertNotIn("host-secret", " ".join(command))

    def test_stale_or_wrong_run_audit_records_are_rejected(self) -> None:
        run_id = "r-sandbox-current"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            event_directory = output / ".r-sandbox"
            event_directory.mkdir()
            event_file = event_directory / f"events-{run_id}.jsonl"
            event_file.write_text(
                json.dumps(
                    {
                        "run_id": "r-sandbox-stale",
                        "event_type": "runtime",
                        "action": "audit_hook",
                        "target": "python",
                        "allowed": True,
                        "detail": "forged stale handshake",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            events = supervisor_module._load_python_audit_events(
                output,
                run_id=run_id,
            )
        self.assertTrue(
            any(event.event_type == "observer" and not event.allowed for event in events)
        )
        self.assertFalse(
            any(
                event.event_type == "runtime"
                and event.action == "audit_hook"
                and event.allowed
                for event in events
            )
        )

    def test_oversized_json_integer_in_audit_log_is_quarantined(self) -> None:
        run_id = "r-sandbox-current"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            event_directory = output / ".r-sandbox"
            event_directory.mkdir()
            event_file = event_directory / f"events-{run_id}.jsonl"
            event_file.write_text(
                '{"run_id":' + ("9" * 5000) + '}\n',
                encoding="utf-8",
            )
            events = supervisor_module._load_python_audit_events(
                output,
                run_id=run_id,
            )
        self.assertTrue(
            any(event.event_type == "observer" and not event.allowed for event in events)
        )


class ManifestBudgetTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "POSIX FIFO behavior")
    def test_fifo_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            os.mkfifo(output / "artifact.pipe")
            with self.assertRaisesRegex(ValueError, "non-regular"):
                capture_output_manifest(output)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(socket, "AF_UNIX"),
        "POSIX Unix-domain socket behavior",
    )
    def test_unix_socket_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            path = output / "artifact.sock"
            endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                endpoint.bind(str(path))
                with self.assertRaisesRegex(ValueError, "non-regular"):
                    capture_output_manifest(output)
            finally:
                endpoint.close()
                path.unlink(missing_ok=True)
    @unittest.skipUnless(os.name == "nt", "Windows junction behavior")
    def test_output_junction_is_never_traversed_or_used_for_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "output"
            outside = base / "outside"
            output.mkdir()
            outside.mkdir()
            (outside / "secret.txt").write_text("outside", encoding="utf-8")
            junction = output / ".r-sandbox"
            created = subprocess.run(
                [
                    "cmd.exe",
                    "/d",
                    "/c",
                    "mklink",
                    "/J",
                    str(junction),
                    str(outside),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest(f"Could not create directory junction: {created.stderr}")
            try:
                with self.assertRaises(ValueError):
                    capture_output_manifest(output)
                with self.assertRaises(supervisor_module.ExecutionPolicyError):
                    supervisor_module._prepare_python_audit_log(
                        output, "r-sandbox-junction-test"
                    )
                self.assertTrue((outside / "secret.txt").is_file())
            finally:
                junction.rmdir()

    def test_file_count_limit_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for index in range(3):
                (output / f"{index}.txt").write_text("x", encoding="utf-8")
            with self.assertRaises(ManifestLimitExceeded) as raised:
                capture_output_manifest(output, max_files=2)

        self.assertEqual(raised.exception.limit_name, "max_files")
        self.assertEqual(raised.exception.observed, 3)

    def test_total_byte_limit_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "a.bin").write_bytes(b"a" * 5)
            (output / "b.bin").write_bytes(b"b" * 5)
            with self.assertRaises(ManifestLimitExceeded) as raised:
                capture_output_manifest(output, max_total_bytes=9)

        self.assertEqual(raised.exception.limit_name, "max_total_bytes")
        self.assertEqual(raised.exception.observed, 10)

    def test_depth_limit_fails_closed_before_deep_recursion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "one" / "two").mkdir(parents=True)
            with self.assertRaises(ManifestLimitExceeded) as raised:
                capture_output_manifest(output, max_depth=1)

        self.assertEqual(raised.exception.limit_name, "max_depth")
        self.assertEqual(raised.exception.observed, 2)

    def test_directory_traversal_limit_bounds_empty_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "one").mkdir()
            (output / "two").mkdir()
            with self.assertRaises(ManifestLimitExceeded) as raised:
                capture_output_manifest(output, max_directories=2)

        self.assertEqual(raised.exception.limit_name, "max_directories")
        self.assertEqual(raised.exception.observed, 3)


if __name__ == "__main__":
    unittest.main()
