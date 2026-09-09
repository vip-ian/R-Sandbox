"""R-Sandbox Python shadow-execution audit hook.

This module is mounted read-only and imported through Python's normal ``site``
startup. Docker remains the security boundary; the hook supplies richer
attempted-behavior evidence and denies high-risk operations early.
"""

from __future__ import annotations

import json
import os
import sys
import time
from urllib.parse import urlsplit


_EVENT_LOG = os.environ.get("R_SANDBOX_EVENT_LOG", "/output/.r-sandbox/events.jsonl")
_RUN_ID = os.environ.get("R_SANDBOX_RUN_ID", "")
_WORKSPACE_ROOT = os.path.realpath("/workspace")
_OUTPUT_ROOT = os.path.realpath("/output")
_TEMP_ROOT = os.path.realpath("/tmp")
_SHM_ROOT = os.path.realpath("/dev/shm")
_AUDIT_ROOT = os.path.realpath("/opt/r-sandbox-audit")
_RUNTIME_ROOTS = tuple(
    dict.fromkeys(
        os.path.realpath(value)
        for value in (sys.prefix, sys.exec_prefix, sys.base_prefix)
        if value
    )
)
_SAFE_DEVICE_READS = frozenset({"/dev/null", "/dev/random", "/dev/urandom"})
_MAX_EVENTS = 10_000


def _target(value: object, limit: int = 500) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    rendered = (
        repr(value)
        if isinstance(value, (tuple, list, dict))
        else str(value)
        if isinstance(value, (str, int, float))
        else type(value).__name__
    )
    return rendered.replace("\x00", "").replace("\r", " ").replace("\n", " ")[:limit]


def _host_port(host: object, port: object | None = None) -> str:
    rendered_host = _target(host, 255).strip("[]")
    if not rendered_host or rendered_host in {"<dynamic>", "None"}:
        return "<unknown-host>"
    if ":" in rendered_host:
        rendered_host = f"[{rendered_host}]"
    if isinstance(port, int) and 0 < port <= 65535:
        return f"{rendered_host}:{port}"
    return rendered_host


def _url_endpoint(value: object) -> str:
    if not isinstance(value, (str, bytes)):
        return "<invalid-url>"
    try:
        parsed = urlsplit(os.fsdecode(value))
        host = parsed.hostname
        port = parsed.port
    except (OSError, TypeError, UnicodeError, ValueError):
        return "<invalid-url>"
    if not host:
        return "<invalid-url>"
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80 if parsed.scheme.lower() == "http" else None
    return _host_port(host, port)


def _url_has_query(value: object) -> bool:
    """Inspect query presence without ever returning or recording its contents."""

    if not isinstance(value, (str, bytes)):
        return True
    try:
        return bool(urlsplit(os.fsdecode(value)).query)
    except (OSError, TypeError, UnicodeError, ValueError):
        return True


def _urllib_action(args: tuple[object, ...]) -> str:
    """Only attest a payload-free, header-free, query-free GET/HEAD as download."""

    url = args[0] if args else None
    data = args[1] if len(args) > 1 else None
    headers = args[2] if len(args) > 2 else None
    method = args[3] if len(args) > 3 and isinstance(args[3], str) else "GET"
    if method.upper() not in {"GET", "HEAD"}:
        return "send"
    if data is not None and data != b"" and data != "":
        return "send"
    if headers:
        return "connect_unknown"
    if _url_has_query(url):
        return "connect_unknown"
    return "download"


def _socket_endpoint(args: tuple[object, ...]) -> str:
    address = args[1] if len(args) > 1 else None
    if isinstance(address, tuple) and address:
        return _host_port(address[0], address[1] if len(address) > 1 else None)
    return _host_port(address)


def _process_event_target(event: str) -> str:
    """Name only the audited API; command paths and arguments are sensitive."""

    return "subprocess" if event == "subprocess.Popen" else event


def _install_audit_hook() -> None:
    """Install a target-visible evidence hook without exported mutable state.

    The log descriptor is opened before registration so recording does not
    recursively trigger the hook's ``open`` branch.  The callback, recorder,
    descriptor, recursion guard, and event counter remain reachable only from
    the registered callback's closure; no ordinary module global can disable
    them.  This removes a trivial toggle, but it does not turn Python-level
    instrumentation into a security boundary: target code can still tamper
    with its process, descriptors, interpreter, or native extensions.
    """

    event_descriptor = -1
    try:
        os.makedirs(os.path.dirname(_EVENT_LOG), exist_ok=True)
        event_descriptor = os.open(
            _EVENT_LOG,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_TRUNC
            | os.O_APPEND
            | getattr(os, "O_BINARY", 0),
            0o600,
        )
        os.set_inheritable(event_descriptor, False)
    except Exception:
        if event_descriptor >= 0:
            try:
                os.close(event_descriptor)
            except OSError:
                pass
        event_descriptor = -1

    writing = False
    event_count = 0
    write_bytes = os.write
    render_target = _target
    timestamp_ns = time.time_ns
    serialize_json = json.dumps
    process_event_target = _process_event_target
    socket_endpoint = _socket_endpoint
    urllib_action = _urllib_action
    url_endpoint = _url_endpoint
    host_port = _host_port
    workspace_root = _WORKSPACE_ROOT
    output_root = _OUTPUT_ROOT
    temp_root = _TEMP_ROOT
    shm_root = _SHM_ROOT
    audit_root = _AUDIT_ROOT
    runtime_roots = _RUNTIME_ROOTS
    safe_device_reads = _SAFE_DEVICE_READS
    run_id = _RUN_ID
    max_events = _MAX_EVENTS
    realpath = os.path.realpath
    commonpath = os.path.commonpath
    abspath = os.path.abspath
    fsdecode = os.fsdecode
    path_types = (str, bytes, os.PathLike)
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

    def path_from(args: tuple[object, ...], index: int = 0) -> str | None:
        if len(args) <= index or not isinstance(args[index], path_types):
            return None
        try:
            return abspath(fsdecode(args[index]))
        except (OSError, TypeError, ValueError):
            return None

    def open_is_write(args: tuple[object, ...]) -> bool:
        mode = args[1] if len(args) > 1 else "r"
        flags = args[2] if len(args) > 2 else 0
        if isinstance(mode, str) and any(marker in mode for marker in "wax+"):
            return True
        return isinstance(flags, int) and bool(flags & write_flags)

    def inside(path: str, root: str) -> bool:
        try:
            return commonpath((realpath(path), root)) == root
        except (OSError, TypeError, ValueError):
            return False

    def writable(path: str | None) -> bool:
        return path is not None and (
            inside(path, output_root)
            or inside(path, temp_root)
            or inside(path, shm_root)
        )

    def readable(path: str | None) -> bool:
        if path is None:
            return False
        resolved = realpath(path)
        return (
            resolved in safe_device_reads
            or inside(resolved, workspace_root)
            or inside(resolved, output_root)
            or inside(resolved, temp_root)
            or inside(resolved, shm_root)
            or inside(resolved, audit_root)
            or any(inside(resolved, root) for root in runtime_roots)
        )

    def record(
        event_type: str,
        action: str,
        target: object,
        allowed: bool,
        detail: str = "",
    ) -> None:
        nonlocal writing, event_count
        if writing or event_count >= max_events or event_descriptor < 0:
            return
        if event_count == max_events - 1:
            event_type = "observer"
            action = "event_limit"
            target = "python-audit"
            allowed = False
            detail = f"Audit event limit reached at {max_events}; later events were dropped."
        writing = True
        try:
            payload = {
                "run_id": run_id,
                "timestamp_ns": timestamp_ns(),
                "event_type": event_type,
                "action": action,
                "target": render_target(target),
                "allowed": bool(allowed),
                "detail": render_target(detail),
            }
            encoded = (
                serialize_json(payload, ensure_ascii=True, sort_keys=True) + "\n"
            ).encode("utf-8")
            offset = 0
            while offset < len(encoded):
                written = write_bytes(event_descriptor, encoded[offset:])
                if written <= 0:
                    raise OSError("audit event write made no progress")
                offset += written
            event_count += 1
        except Exception:
            pass
        finally:
            writing = False

    def deny(event_type: str, action: str, target: object, detail: str) -> None:
        record(event_type, action, target, False, detail)
        raise PermissionError(
            f"R-Sandbox shadow policy blocked {action}: {render_target(target)}"
        )

    def audit(event: str, args: tuple[object, ...]) -> None:
        if writing:
            return
        if event == "open":
            path = path_from(args)
            write = open_is_write(args)
            action = "write" if write else "read"
            if write and not writable(path):
                deny("filesystem", action, path or args[0], "write outside /output or /tmp")
            if not write and path is not None and not readable(path):
                deny(
                    "filesystem",
                    action,
                    path,
                    "read outside the snapshot, output, temporary, or trusted runtime roots",
                )
            if write or path is not None:
                record("filesystem", action, path or args[0], True)
            return
        if event in {"os.system", "os.exec", "os.posix_spawn", "pty.spawn"}:
            deny(
                "process",
                "spawn",
                process_event_target(event),
                f"blocked audit event {event}",
            )
        if event == "subprocess.Popen":
            deny(
                "process",
                "spawn",
                process_event_target(event),
                "subprocess creation is disabled in shadow mode",
            )
        if event in {"socket.connect", "socket.connect_ex"}:
            deny(
                "network",
                "connect",
                socket_endpoint(args),
                f"blocked audit event {event}",
            )
        if event == "socket.sendto":
            deny(
                "network",
                "send",
                socket_endpoint(args),
                f"blocked audit event {event}",
            )
        if event == "urllib.Request":
            action = urllib_action(args)
            target = url_endpoint(args[0] if args else None)
            deny("network", action, target, f"blocked audit event {event}")
        if event == "http.client.connect":
            host = args[1] if len(args) > 1 else None
            port = args[2] if len(args) > 2 else None
            deny("network", "connect", host_port(host, port), f"blocked audit event {event}")
        if event in {
            "os.remove",
            "os.rmdir",
            "os.mkdir",
            "os.chmod",
            "os.chown",
            "os.truncate",
            "os.utime",
        }:
            path = path_from(args)
            if not writable(path):
                deny("filesystem", "mutate", path or event, f"blocked audit event {event}")
            record("filesystem", "mutate", path or event, True, event)
            return
        if event in {"os.rename", "os.replace"}:
            source = path_from(args, 0)
            destination = path_from(args, 1)
            if not writable(source) or not writable(destination):
                violating_path = source if not writable(source) else destination
                deny(
                    "filesystem",
                    "rename",
                    render_target(violating_path),
                    f"blocked audit event {event}",
                )
            record("filesystem", "rename", render_target(destination), True, event)

    sys.addaudithook(audit)
    record("runtime", "audit_hook", "python", True, "shadow audit hook installed")

    # `python -P` keeps the untrusted script/cwd directory out of sys.path while
    # this trusted module and its dependencies load. Restore project-local
    # import compatibility only after the audit hook is registered.
    if os.environ.get("R_SANDBOX_SHADOW_MODE") == "1":
        try:
            while workspace_root in sys.path:
                sys.path.remove(workspace_root)
            sys.path.append(workspace_root)
        except (AttributeError, TypeError, ValueError):
            record(
                "observer",
                "audit_path",
                "python",
                False,
                "workspace import path could not be installed after the audit hook",
            )


_install_audit_hook()
del _install_audit_hook
