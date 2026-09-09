"""Loopback-only HTTP dashboard for running and reviewing R-Sandbox reports."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import shutil
import threading
import time
from typing import Any, Callable
from urllib.parse import urlsplit
import webbrowser

from r_sandbox.agent.orchestrator import AgentMode, RSandboxAgent


_STATIC_ROOT = Path(__file__).with_name("static")
_MAX_REQUEST_BYTES = 65_536
_MAX_LIST_ITEMS = 256
_DEFAULT_IMAGE = "python:3.11-slim"
_CONTENT_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
}


class DashboardServer(ThreadingHTTPServer):
    """HTTP server carrying one ephemeral UI authorization context."""

    daemon_threads = False
    block_on_close = True

    session_token: str
    run_lock: threading.Lock
    project_root: Path
    agent_factory: Callable[[], RSandboxAgent]


def _bounded_text(
    value: object,
    field: str,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str:
        raise ValueError(f"{field} must be text")
    normalized = value.strip()
    if (not allow_empty and not normalized) or len(normalized) > maximum or "\x00" in normalized:
        raise ValueError(f"{field} is empty or exceeds its safety limit")
    try:
        normalized.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field} must be valid UTF-8 text") from error
    return normalized


def _bounded_string_set(value: object, field: str) -> frozenset[str]:
    if type(value) is not list or len(value) > _MAX_LIST_ITEMS:
        raise ValueError(f"{field} must be a bounded list")
    return frozenset(
        _bounded_text(item, f"{field} item", maximum=8_192)
        for item in value
    )


def _run_request(
    payload: object,
    *,
    agent_factory: Callable[[], RSandboxAgent],
) -> dict[str, Any]:
    if type(payload) is not dict:
        raise ValueError("request body must be a JSON object")
    allowed_keys = {
        "repository",
        "goal",
        "output",
        "mode",
        "image",
        "approved_request_ids",
        "network_allowlist",
        "confirm_shadow",
    }
    if set(payload) - allowed_keys:
        raise ValueError("request contains unsupported fields")

    repository_text = _bounded_text(
        payload.get("repository"),
        "repository",
        maximum=32_768,
    )
    goal = _bounded_text(payload.get("goal"), "goal", maximum=16_384)
    mode_text = _bounded_text(payload.get("mode"), "mode", maximum=32)
    image = _bounded_text(
        payload.get("image", _DEFAULT_IMAGE),
        "image",
        maximum=255,
    )
    try:
        mode = AgentMode(mode_text)
    except ValueError as error:
        raise ValueError("mode must be analyze, dry-run, or shadow") from error
    if mode == AgentMode.SHADOW and payload.get("confirm_shadow") is not True:
        raise ValueError("shadow mode requires an explicit confirmation")

    repository = Path(repository_text).expanduser().resolve(strict=True)
    if not repository.is_dir():
        raise ValueError("repository must be an existing directory")
    output_text = _bounded_text(
        payload.get("output", ""),
        "output",
        maximum=32_768,
        allow_empty=True,
    )
    output = (
        Path(output_text).expanduser().resolve(strict=False)
        if output_text
        else (repository.parent / f".{repository.name}-r-sandbox" / "output").resolve(
            strict=False
        )
    )
    approved = _bounded_string_set(
        payload.get("approved_request_ids", []),
        "approved_request_ids",
    )
    allowlist = _bounded_string_set(
        payload.get("network_allowlist", []),
        "network_allowlist",
    )

    started = time.monotonic()
    report = agent_factory().run(
        repository,
        goal,
        output=output,
        mode=mode,
        image=image,
        approved_request_ids=approved,
        network_allowlist=allowlist,
    )
    return {
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "mode": mode.value,
        "report": report.to_dict(),
    }


def _bootstrap_payload(server: DashboardServer) -> dict[str, Any]:
    example = server.project_root / "examples" / "safe_research_repo"
    repository = example if example.is_dir() else server.project_root
    return {
        "docker_cli_available": shutil.which("docker") is not None,
        "default_repository": str(repository.resolve()),
        "default_image": _DEFAULT_IMAGE,
        "modes": [mode.value for mode in AgentMode],
        "privacy": (
            "Reports can contain local paths and security metadata. "
            "Review them before sharing."
        ),
    }


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve trusted static assets and one authenticated local JSON endpoint."""

    protocol_version = "HTTP/1.1"
    server_version = "R-Sandbox-UI/0.1"
    sys_version = ""

    @property
    def dashboard_server(self) -> DashboardServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, _format: str, *args: object) -> None:
        return

    def _set_security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _send_bytes(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        head_only: bool = False,
    ) -> None:
        self.close_connection = True
        self.send_response(status)
        self._set_security_headers()
        self.send_header("Connection", "close")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _host_is_local(self) -> bool:
        expected = f"127.0.0.1:{self.dashboard_server.server_port}"
        return self.headers.get("Host", "") == expected

    def _authorized(self, *, require_origin: bool) -> bool:
        if not self._host_is_local():
            return False
        supplied = self.headers.get("X-R-Sandbox-Token", "")
        if not supplied or not secrets.compare_digest(
            supplied,
            self.dashboard_server.session_token,
        ):
            return False
        if require_origin:
            expected = f"http://127.0.0.1:{self.dashboard_server.server_port}"
            if self.headers.get("Origin", "") != expected:
                return False
        return True

    def _serve_static(self, *, head_only: bool = False) -> None:
        parsed = urlsplit(self.path)
        if parsed.query:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        path = parsed.path
        relative = {
            "/": "index.html",
            "/index.html": "index.html",
            "/styles.css": "styles.css",
            "/app.js": "app.js",
        }.get(path)
        if relative is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        target = _STATIC_ROOT / relative
        try:
            body = target.read_bytes()
        except OSError:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "dashboard asset is unavailable"},
            )
            return
        self._send_bytes(
            HTTPStatus.OK,
            body,
            _CONTENT_TYPES[target.suffix],
            head_only=head_only,
        )

    def do_HEAD(self) -> None:
        self._serve_static(head_only=True)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.query:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if parsed.path == "/api/bootstrap":
            if not self._authorized(require_origin=False):
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            self._send_json(
                HTTPStatus.OK,
                _bootstrap_payload(self.dashboard_server),
            )
            return
        self._serve_static()

    def _read_json_body(self) -> object:
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("chunked request bodies are not accepted")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            raise ValueError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError as error:
            raise ValueError("Content-Length is required") from error
        if not 0 < length <= _MAX_REQUEST_BYTES:
            raise ValueError("request body exceeds its safety limit")
        body = self.rfile.read(length)
        try:
            return json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("request body must be valid UTF-8 JSON") from error

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.query or parsed.path != "/api/run":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._authorized(require_origin=True):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return
        if not self.dashboard_server.run_lock.acquire(blocking=False):
            self._send_json(
                HTTPStatus.CONFLICT,
                {"error": "another security check is already running"},
            )
            return
        try:
            payload = self._read_json_body()
            result = _run_request(
                payload,
                agent_factory=self.dashboard_server.agent_factory,
            )
        except (OSError, TypeError, ValueError) as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        except Exception:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "the local agent could not complete this check"},
            )
            return
        finally:
            self.dashboard_server.run_lock.release()
        self._send_json(HTTPStatus.OK, result)

    def do_OPTIONS(self) -> None:
        self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"})


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object keys are not accepted")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON value is not accepted: {value}")


def create_dashboard_server(
    *,
    port: int = 8765,
    project_root: Path | None = None,
    token: str | None = None,
    agent_factory: Callable[[], RSandboxAgent] = RSandboxAgent,
) -> DashboardServer:
    """Create a loopback-only dashboard server without starting its loop."""

    if type(port) is not int or not 0 <= port <= 65_535:
        raise ValueError("dashboard port must be an integer in 0..65535")
    server = DashboardServer(("127.0.0.1", port), DashboardHandler)
    server.session_token = token or secrets.token_urlsafe(32)
    server.run_lock = threading.Lock()
    server.project_root = (project_root or Path.cwd()).resolve(strict=True)
    server.agent_factory = agent_factory
    return server


def dashboard_url(server: DashboardServer) -> str:
    """Return the authenticated browser URL for a dashboard server."""

    return (
        f"http://127.0.0.1:{server.server_port}/"
        f"#token={server.session_token}"
    )


def serve_dashboard(*, port: int = 8765, open_browser: bool = True) -> int:
    """Run the local dashboard until interrupted."""

    server = create_dashboard_server(port=port)
    url = dashboard_url(server)
    print(f"R-Sandbox UI: {url}", flush=True)
    print("Press Ctrl+C to stop the local UI.", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nR-Sandbox UI stopped.", flush=True)
    finally:
        server.shutdown()
        server.server_close()
    return 0
