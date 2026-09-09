from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest

from r_sandbox.cli import main


class CliErrorHandlingTests(unittest.TestCase):
    def test_missing_repository_returns_controlled_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            stderr = io.StringIO()
            with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
                exit_code = main(
                    ["analyze", str(missing), "--goal", "inspect the experiment"]
                )
        self.assertEqual(exit_code, 2)
        self.assertIn("r-sandbox:", stderr.getvalue())

    def test_report_inside_untrusted_repository_is_rejected_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "project"
            repository.mkdir()
            (repository / "train.py").write_text(
                "if __name__ == '__main__':\n    print('ok')\n",
                encoding="utf-8",
            )
            report_directory = repository / "should-not-exist"
            report_path = report_directory / "report.json"
            stderr = io.StringIO()
            stdout = io.StringIO()
            with redirect_stderr(stderr), redirect_stdout(stdout):
                exit_code = main(
                    [
                        "analyze",
                        str(repository),
                        "--goal",
                        "inspect the experiment",
                        "--report",
                        str(report_path),
                    ]
                )
            self.assertFalse(report_path.exists())
            self.assertFalse(report_directory.exists())
        self.assertEqual(exit_code, 2)
        self.assertIn("disjoint", stderr.getvalue())
        self.assertIn('"security_assessment"', stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
