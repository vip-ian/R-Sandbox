from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIRECTORY = (
    ROOT
    / "src"
    / "r_sandbox"
    / "tools"
    / "execution_supervisor"
    / "python_audit"
)


class PythonAuditTests(unittest.TestCase):
    def _run_audit(self, source: str) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory() as directory:
            event_log = Path(directory) / "events.jsonl"
            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHONPATH": str(AUDIT_DIRECTORY),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "R_SANDBOX_EVENT_LOG": str(event_log),
                    "R_SANDBOX_SHADOW_MODE": "1",
                }
            )
            completed = subprocess.run(
                (sys.executable, "-c", source),
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
                check=False,
            )
            raw = event_log.read_text(encoding="utf-8")
        return completed, raw

    def test_urllib_event_records_only_endpoint_not_url_or_body(self) -> None:
        completed, raw = self._run_audit(
            "import sys; "
            "sys.audit('urllib.Request', "
            "'https://datasets.example.org/private?token=url-secret', "
            "b'body-secret', {}, 'POST')"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("url-secret", raw)
        self.assertNotIn("body-secret", raw)
        events = [json.loads(line) for line in raw.splitlines()]
        network = [event for event in events if event["event_type"] == "network"]
        self.assertEqual(network[-1]["action"], "send")
        self.assertEqual(network[-1]["target"], "datasets.example.org:443")

    def test_socket_tuple_is_normalized_for_host_correlation(self) -> None:
        completed, raw = self._run_audit(
            "import sys; "
            "sys.audit('socket.connect', object(), ('datasets.example.org', 443))"
        )
        self.assertNotEqual(completed.returncode, 0)
        events = [json.loads(line) for line in raw.splitlines()]
        network = [event for event in events if event["event_type"] == "network"]
        self.assertEqual(network[-1]["target"], "datasets.example.org:443")

    def test_get_with_secret_header_is_not_attested_as_download(self) -> None:
        completed, raw = self._run_audit(
            "import sys; "
            "sys.audit('urllib.Request', "
            "'https://datasets.example.org/data', None, "
            "{'Authorization': 'Bearer header-secret'}, 'GET')"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("header-secret", raw)
        events = [json.loads(line) for line in raw.splitlines()]
        network = [event for event in events if event["event_type"] == "network"]
        self.assertEqual(network[-1]["action"], "connect_unknown")
        self.assertEqual(network[-1]["target"], "datasets.example.org:443")

    def test_get_with_query_is_not_attested_as_download(self) -> None:
        completed, raw = self._run_audit(
            "import sys; "
            "sys.audit('urllib.Request', "
            "'https://datasets.example.org/data?token=query-secret', "
            "None, {}, 'GET')"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn("query-secret", raw)
        events = [json.loads(line) for line in raw.splitlines()]
        network = [event for event in events if event["event_type"] == "network"]
        self.assertEqual(network[-1]["action"], "connect_unknown")

    def test_process_events_and_errors_never_record_commands_or_paths(self) -> None:
        cases = (
            (
                "import sys\n"
                "try:\n"
                "    sys.audit('os.system', "
                "'curl --header Authorization:runtime-command-secret example.invalid')\n"
                "except PermissionError as error:\n"
                "    print(str(error), file=sys.stderr)\n"
                "    raise SystemExit(7)\n",
                ("runtime-command-secret",),
                "os.system",
            ),
            (
                "import sys\n"
                "try:\n"
                "    sys.audit('subprocess.Popen', "
                "'/private/runtime-path-secret/python', "
                "['/private/runtime-path-secret/python', "
                "'--token=runtime-argument-secret'], None, None)\n"
                "except PermissionError as error:\n"
                "    print(str(error), file=sys.stderr)\n"
                "    raise SystemExit(7)\n",
                ("runtime-path-secret", "runtime-argument-secret"),
                "subprocess",
            ),
        )
        for source, secrets, expected_target in cases:
            with self.subTest(expected_target=expected_target):
                completed, raw = self._run_audit(source)
                self.assertNotEqual(completed.returncode, 0)
                serialized = raw + completed.stdout + completed.stderr
                for secret in secrets:
                    self.assertNotIn(secret, serialized)
                events = [json.loads(line) for line in raw.splitlines()]
                process = [
                    event for event in events if event["event_type"] == "process"
                ]
                self.assertEqual(process[-1]["target"], expected_target)
                self.assertFalse(process[-1]["allowed"])

    def test_legacy_module_flag_cannot_disable_registered_hook(self) -> None:
        completed, raw = self._run_audit(
            "import os, sitecustomize\n"
            "assert all(not hasattr(sitecustomize, name) for name in "
            "('_WRITING', '_audit', '_deny', '_record', '_path_from', "
            "'_open_is_write', '_install_audit_hook'))\n"
            "sitecustomize._WRITING = True\n"
            "sitecustomize._audit = lambda *args: None\n"
            "sitecustomize._deny = lambda *args: None\n"
            "sitecustomize._record = lambda *args: None\n"
            "sitecustomize._path_from = lambda *args: '/output/forged'\n"
            "sitecustomize._open_is_write = lambda *args: False\n"
            "os.system('r-sandbox-command-must-not-run')\n"
        )
        self.assertNotEqual(completed.returncode, 0)
        events = [json.loads(line) for line in raw.splitlines()]
        process = [event for event in events if event["event_type"] == "process"]
        self.assertTrue(process)
        self.assertEqual(process[-1]["target"], "os.system")
        self.assertFalse(process[-1]["allowed"])
        self.assertNotIn("r-sandbox-command-must-not-run", raw)

    def test_forged_module_helpers_cannot_turn_workspace_write_into_read(self) -> None:
        completed, raw = self._run_audit(
            "import sitecustomize, sys\n"
            "sitecustomize._path_from = lambda *args: '/output/forged'\n"
            "sitecustomize._open_is_write = lambda *args: False\n"
            "sys.audit('open', '/workspace/experiment.py', 'w', 0)\n"
        )
        self.assertNotEqual(completed.returncode, 0)
        events = [json.loads(line) for line in raw.splitlines()]
        writes = [
            event
            for event in events
            if event["event_type"] == "filesystem"
            and event["action"] == "write"
        ]
        self.assertTrue(writes)
        self.assertFalse(writes[-1]["allowed"])

    def test_private_shared_memory_matches_authorized_scratch_contract(self) -> None:
        completed, raw = self._run_audit(
            "import sys; sys.audit('open', '/dev/shm/test-buffer', 'w', 0)"
        )
        self.assertEqual(completed.returncode, 0)
        events = [json.loads(line) for line in raw.splitlines()]
        writes = [
            event
            for event in events
            if event["event_type"] == "filesystem" and event["action"] == "write"
        ]
        self.assertTrue(writes)
        self.assertTrue(writes[-1]["allowed"])


if __name__ == "__main__":
    unittest.main()
