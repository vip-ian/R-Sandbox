from __future__ import annotations

from contextlib import redirect_stdout
from http import HTTPStatus
from pathlib import Path
import io
import json
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from r_sandbox.cli import main
from r_sandbox.ui.server import create_dashboard_server


ROOT = Path(__file__).resolve().parents[1]
SAFE = ROOT / "examples" / "safe_research_repo"
STATIC = ROOT / "src" / "r_sandbox" / "ui" / "static"


class DashboardServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.token = "test-session-token"
        self.server = create_dashboard_server(
            port=0,
            project_root=ROOT,
            token=self.token,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temporary.cleanup()

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: bytes | None = None,
        token: str | None = None,
        origin: str | None = None,
        content_type: str | None = None,
        host: str | None = None,
    ) -> tuple[int, dict[str, object], dict[str, str]]:
        headers: dict[str, str] = {}
        if token is not None:
            headers["X-R-Sandbox-Token"] = token
        if origin is not None:
            headers["Origin"] = origin
        if content_type is not None:
            headers["Content-Type"] = content_type
        if host is not None:
            headers["Host"] = host
        request = Request(
            self.origin + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            response = urlopen(request, timeout=10)
        except HTTPError as error:
            response = error
        with response:
            raw = response.read()
            payload = json.loads(raw.decode("utf-8")) if raw else {}
            return response.status, payload, dict(response.headers.items())

    def test_static_page_has_security_headers_and_no_dynamic_html_sink(self) -> None:
        response = urlopen(self.origin + "/", timeout=5)
        with response:
            page = response.read().decode("utf-8")
            self.assertEqual(response.status, HTTPStatus.OK)
            self.assertIn("R-Sandbox", page)
            self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")
            self.assertEqual(response.headers["Connection"], "close")
        javascript = (STATIC / "app.js").read_text(encoding="utf-8")
        self.assertNotIn("innerHTML", javascript)

    def test_api_requires_session_token_and_exact_origin(self) -> None:
        status, payload, headers = self.request("/api/bootstrap")
        self.assertEqual(status, HTTPStatus.FORBIDDEN)
        self.assertEqual(payload["error"], "forbidden")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

        status, payload, _ = self.request(
            "/api/bootstrap",
            token=self.token,
            host="attacker.invalid",
        )
        self.assertEqual(status, HTTPStatus.FORBIDDEN)
        self.assertEqual(payload["error"], "forbidden")

        body = json.dumps(self.valid_payload()).encode("utf-8")
        status, _, _ = self.request(
            "/api/run",
            method="POST",
            body=body,
            token=self.token,
            origin="https://attacker.invalid",
            content_type="application/json",
        )
        self.assertEqual(status, HTTPStatus.FORBIDDEN)

    def test_analyze_request_returns_sanitized_agent_report(self) -> None:
        body = json.dumps(self.valid_payload()).encode("utf-8")
        status, payload, _ = self.request(
            "/api/run",
            method="POST",
            body=body,
            token=self.token,
            origin=self.origin,
            content_type="application/json",
        )
        self.assertEqual(status, HTTPStatus.OK)
        report = payload["report"]
        self.assertEqual(report["outcome"], "analyzed")
        self.assertEqual(report["security_gate_result"], "inconclusive")
        self.assertIn("authorization", report)

    def test_shadow_requires_explicit_confirmation(self) -> None:
        payload = self.valid_payload()
        payload["mode"] = "shadow"
        body = json.dumps(payload).encode("utf-8")
        status, response, _ = self.request(
            "/api/run",
            method="POST",
            body=body,
            token=self.token,
            origin=self.origin,
            content_type="application/json",
        )
        self.assertEqual(status, HTTPStatus.BAD_REQUEST)
        self.assertIn("explicit confirmation", response["error"])

    def test_duplicate_and_nonfinite_json_are_rejected(self) -> None:
        for body in (
            b'{"repository":"a","repository":"b"}',
            b'{"repository":NaN}',
        ):
            with self.subTest(body=body):
                status, _, _ = self.request(
                    "/api/run",
                    method="POST",
                    body=body,
                    token=self.token,
                    origin=self.origin,
                    content_type="application/json",
                )
                self.assertEqual(status, HTTPStatus.BAD_REQUEST)

    def test_query_strings_and_cross_origin_preflight_are_not_supported(self) -> None:
        status, _, _ = self.request(
            "/api/bootstrap?token=" + self.token,
            token=self.token,
        )
        self.assertEqual(status, HTTPStatus.NOT_FOUND)
        status, _, headers = self.request(
            "/api/run",
            method="OPTIONS",
        )
        self.assertEqual(status, HTTPStatus.METHOD_NOT_ALLOWED)
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def valid_payload(self) -> dict[str, object]:
        return {
            "repository": str(SAFE),
            "goal": "inspect the benign experiment",
            "output": str(Path(self.temporary.name) / "output"),
            "mode": "analyze",
            "image": "python:3.11-slim",
            "approved_request_ids": [],
            "network_allowlist": [],
            "confirm_shadow": False,
        }


class DashboardCliTests(unittest.TestCase):
    def test_ui_subcommand_delegates_to_loopback_server(self) -> None:
        with patch("r_sandbox.ui.serve_dashboard", return_value=0) as serve:
            with redirect_stdout(io.StringIO()):
                result = main(["ui", "--port", "0", "--no-open"])
        self.assertEqual(result, 0)
        serve.assert_called_once_with(port=0, open_browser=False)


if __name__ == "__main__":
    unittest.main()
