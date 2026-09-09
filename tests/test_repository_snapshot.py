from __future__ import annotations

from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from r_sandbox.agent.orchestrator import AgentMode, RSandboxAgent
from r_sandbox.agent.reporter import ReportGenerator
from r_sandbox.models import AgentOutcome, ExecutionResult, RuntimeEvent
from r_sandbox.tools.repository_snapshot import RepositorySnapshotter, SnapshotLimits


class InspectingSupervisor:
    def __init__(self) -> None:
        self.repository: Path | None = None
        self.secret_was_visible = True

    def execute(self, spec):
        self.repository = Path(spec.repository)
        self.secret_was_visible = (self.repository / ".env").exists()
        return ExecutionResult(
            status=AgentOutcome.SUCCEEDED,
            exit_code=0,
            events=(RuntimeEvent("runtime", "audit_hook", "python", True),),
        )


class RepositorySnapshotTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "requires POSIX byte filenames")
    def test_invalid_byte_filename_is_digest_distinct_and_report_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "project"
            source.mkdir()
            (source / "train.py").write_text("print('ok')\n", encoding="utf-8")
            source_bytes = os.fsencode(source)
            first_path = source_bytes + b"/invalid-\xff.py"
            second_path = source_bytes + b"/invalid-\xfe.py"
            descriptor = os.open(first_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(descriptor, b"print('external-name')\n")
            finally:
                os.close(descriptor)

            snapshotter = RepositorySnapshotter()
            with snapshotter.create(source) as first:
                first_digest = first.digest
                self.assertFalse(first.complete)
                self.assertTrue(all("\\x" in item for item in first.omitted_paths))
            os.rename(first_path, second_path)
            with snapshotter.create(source) as second:
                self.assertNotEqual(second.digest, first_digest)
                self.assertFalse(second.complete)

            report = RSandboxAgent().run(
                source,
                "inspect safely",
                output=Path(directory) / "output",
            )
            ReportGenerator().json_text(report).encode("utf-8", errors="strict")
            ReportGenerator().markdown(report).encode("utf-8", errors="strict")

    @unittest.skipUnless(os.name == "posix", "requires POSIX byte filenames")
    def test_invalid_byte_repository_root_is_identity_bound_and_report_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root_bytes = os.fsencode(directory) + b"/project-\xff"
            os.mkdir(root_bytes, 0o700)
            source = Path(os.fsdecode(root_bytes))
            (source / "train.py").write_text("print('ok')\n", encoding="utf-8")

            report = RSandboxAgent().run(
                source,
                "inspect safely",
                output=Path(directory) / "output",
            )
            json_text = ReportGenerator().json_text(report)
            markdown = ReportGenerator().markdown(report)

            json_text.encode("utf-8", errors="strict")
            markdown.encode("utf-8", errors="strict")
            self.assertIn("\\udcff", report.to_dict()["repository"])
            self.assertIn("\\udcff", markdown)

    def test_agent_rejects_lone_surrogate_goal_at_api_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "project"
            source.mkdir()
            with self.assertRaisesRegex(ValueError, "valid UTF-8"):
                RSandboxAgent().run(
                    source,
                    "inspect \udcff safely",
                    output=Path(directory) / "output",
                )

    def test_snapshot_withholds_credentials_and_is_content_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "project"
            source.mkdir()
            (source / "train.py").write_text("print('ok')\n", encoding="utf-8")
            (source / ".env").write_text("TOKEN=top-secret\n", encoding="utf-8")
            snapshotter = RepositorySnapshotter()
            with snapshotter.create(source) as first:
                first_digest = first.digest
                self.assertTrue((first.root / "train.py").is_file())
                self.assertFalse((first.root / ".env").exists())
                self.assertIn(".env", first.omitted_paths)
                self.assertTrue(first.warnings)
            with snapshotter.create(source) as second:
                self.assertEqual(second.digest, first_digest)

    def test_shadow_analyzes_and_executes_snapshot_not_source_checkout(self) -> None:
        supervisor = InspectingSupervisor()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "project"
            source.mkdir()
            (source / "train.py").write_text(
                "if __name__ == '__main__':\n    print('ok')\n",
                encoding="utf-8",
            )
            (source / ".env").write_text("TOKEN=top-secret\n", encoding="utf-8")
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                source,
                "run the local experiment",
                output=base / "output",
                mode=AgentMode.SHADOW,
            )
        self.assertIsNotNone(supervisor.repository)
        self.assertNotEqual(supervisor.repository, source)
        self.assertFalse(supervisor.secret_was_visible)
        self.assertEqual(report.profile.root, str(source.resolve()))
        self.assertIn(".env", report.profile.snapshot_omissions)
        self.assertNotEqual(report.security_assessment.verdict.value, "safe")

    def test_snapshot_digest_binds_capabilities_to_repository_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "project"
            source.mkdir()
            script = source / "train.py"
            script.write_text(
                "if __name__ == '__main__':\n    print('one')\n",
                encoding="utf-8",
            )
            agent = RSandboxAgent()
            first = agent.run(source, "run", output=base / "first")
            script.write_text(
                "if __name__ == '__main__':\n    print('two')\n",
                encoding="utf-8",
            )
            second = agent.run(source, "run", output=base / "second")
        self.assertNotEqual(first.profile.snapshot_digest, second.profile.snapshot_digest)
        first_ids = {item.request.request_id for item in first.authorization.decisions}
        second_ids = {item.request.request_id for item in second.authorization.decisions}
        self.assertTrue(first_ids.isdisjoint(second_ids))

    def test_snapshot_limits_fail_closed_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "project"
            source.mkdir()
            (source / "a.py").write_text("print('a')\n", encoding="utf-8")
            (source / "b.py").write_text("print('b')\n", encoding="utf-8")
            snapshotter = RepositorySnapshotter(
                SnapshotLimits(max_files=1, max_directories=2)
            )
            with snapshotter.create(source) as snapshot:
                self.assertFalse(snapshot.complete)
                self.assertEqual(snapshot.files, 1)
                self.assertTrue(snapshot.warnings)

    def test_hard_link_is_omitted_instead_of_importing_external_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "project"
            source.mkdir()
            outside = base / "outside-secret.py"
            canary = b"EXTERNAL_HARDLINK_CANARY"
            outside.write_bytes(canary)
            linked = source / "linked.py"
            try:
                os.link(outside, linked)
            except OSError as error:
                self.skipTest(f"Hard links are unavailable on this filesystem: {error}")
            with RepositorySnapshotter().create(source) as snapshot:
                self.assertFalse(snapshot.complete)
                self.assertFalse((snapshot.root / "linked.py").exists())
                self.assertIn("linked.py", snapshot.omitted_paths)
                self.assertTrue(
                    any("multiply linked" in warning for warning in snapshot.warnings)
                )
                self.assertFalse(
                    any(canary in item.read_bytes() for item in snapshot.root.rglob("*"))
                )

    def test_nested_credential_directories_are_withheld(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "project"
            nested = source / "vendor" / ".ssh"
            nested.mkdir(parents=True)
            (source / "train.py").write_text("print('ok')\n", encoding="utf-8")
            (nested / "custom_private_key").write_text(
                "private material\n", encoding="utf-8"
            )
            with RepositorySnapshotter().create(source) as snapshot:
                self.assertFalse(
                    (snapshot.root / "vendor" / ".ssh" / "custom_private_key").exists()
                )
                self.assertIn("vendor/.ssh", snapshot.omitted_paths)

    def test_common_repository_credential_files_are_withheld(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "project"
            source.mkdir()
            names = (
                ".netrc",
                ".npmrc",
                ".pypirc",
                "client_secret.json",
                "service_account.json",
                "token.json",
            )
            for name in names:
                (source / name).write_text("synthetic-secret\n", encoding="utf-8")
            with RepositorySnapshotter().create(source) as snapshot:
                for name in names:
                    self.assertFalse((snapshot.root / name).exists())
                    self.assertIn(name, snapshot.omitted_paths)

    def test_snapshot_entry_budget_is_global_across_omitted_trees(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "project"
            for branch in ("a", "b"):
                child = source / branch
                child.mkdir(parents=True)
                for index in range(4):
                    (child / f".env.{index}").write_text("x", encoding="utf-8")
            with RepositorySnapshotter(
                SnapshotLimits(max_files=2, max_directories=3)
            ).create(source) as snapshot:
                self.assertFalse(snapshot.complete)
                self.assertTrue(
                    any("entry-count limit" in warning for warning in snapshot.warnings)
                )

    def test_excluded_executable_tree_is_never_silent_or_safe(self) -> None:
        supervisor = InspectingSupervisor()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "project"
            payload = source / "site-packages"
            payload.mkdir(parents=True)
            (source / "train.py").write_text(
                "if __name__ == '__main__':\n    print('fixture')\n",
                encoding="utf-8",
            )
            (payload / "conditional_payload.py").write_text(
                "raise RuntimeError('hidden executable code')\n", encoding="utf-8"
            )
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                source,
                "run the experiment",
                output=base / "output",
                mode=AgentMode.SHADOW,
                image="python@sha256:" + ("2" * 64),
            )
        self.assertIn("site-packages", report.profile.snapshot_omissions)
        self.assertTrue(
            any("executable dependency" in item for item in report.profile.warnings)
        )
        self.assertNotEqual(report.security_assessment.verdict.value, "safe")

    def test_version_control_tree_is_digest_bound_and_warned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "project"
            source.mkdir()
            (source / "train.py").write_text("print('ok')\n", encoding="utf-8")
            snapshotter = RepositorySnapshotter()
            with snapshotter.create(source) as baseline:
                baseline_digest = baseline.digest

            metadata = source / ".git"
            metadata.mkdir()
            (metadata / "config").write_text("[core]\n", encoding="utf-8")
            with snapshotter.create(source) as snapshot:
                self.assertNotEqual(snapshot.digest, baseline_digest)
                self.assertFalse(snapshot.complete)
                self.assertFalse((snapshot.root / ".git").exists())
                self.assertIn(".git", snapshot.omitted_paths)
                self.assertTrue(
                    any(".git" in warning for warning in snapshot.warnings)
                )

    def test_linked_worktree_git_file_is_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "project"
            source.mkdir()
            canary = "gitdir: C:/host/secret/worktree/.git/worktrees/project\n"
            (source / ".git").write_text(canary, encoding="utf-8")
            (source / "train.py").write_text("print('ok')\n", encoding="utf-8")
            with RepositorySnapshotter().create(source) as snapshot:
                self.assertFalse(snapshot.complete)
                self.assertFalse((snapshot.root / ".git").exists())
                self.assertIn(".git", snapshot.omitted_paths)
                self.assertFalse(
                    any(
                        canary.encode() in item.read_bytes()
                        for item in snapshot.root.rglob("*")
                        if item.is_file()
                    )
                )

    def test_declared_nested_mount_is_omitted_before_enumeration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "project"
            mounted = source / "mounted-dataset"
            mounted.mkdir(parents=True)
            canary = b"EXTERNAL_MOUNT_CANARY"
            (mounted / "secret.bin").write_bytes(canary)
            mount_points = frozenset({mounted.resolve()})
            with patch(
                "r_sandbox.tools.repository_snapshot.snapshot._linux_mount_points",
                return_value=mount_points,
            ):
                with RepositorySnapshotter().create(source) as snapshot:
                    self.assertFalse(snapshot.complete)
                    self.assertFalse((snapshot.root / "mounted-dataset").exists())
                    self.assertIn("mounted-dataset", snapshot.omitted_paths)
                    self.assertTrue(
                        any("nested filesystem mount" in item for item in snapshot.warnings)
                    )

    def test_interpreter_cache_omission_prevents_safe_verdict(self) -> None:
        supervisor = InspectingSupervisor()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "project"
            cache = source / "__pycache__"
            cache.mkdir(parents=True)
            (source / "train.py").write_text(
                "if __name__ == '__main__':\n    print('fixture')\n",
                encoding="utf-8",
            )
            (cache / "payload.cpython-311.pyc").write_bytes(b"untrusted-bytecode")
            report = RSandboxAgent(execution_supervisor=supervisor).run(
                source,
                "run the experiment",
                output=base / "output",
                mode=AgentMode.SHADOW,
                image="python@sha256:" + ("2" * 64),
            )

        self.assertIn("__pycache__", report.profile.snapshot_omissions)
        self.assertTrue(
            any("__pycache__" in warning for warning in report.profile.warnings)
        )
        self.assertNotEqual(report.security_assessment.verdict.value, "safe")


if __name__ == "__main__":
    unittest.main()
