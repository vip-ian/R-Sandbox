from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from r_sandbox.agent.repository_understanding import RepositoryUnderstanding
from r_sandbox.agent.reporter import ReportGenerator
from r_sandbox.models import (
    AgentOutcome,
    AgentReport,
    CapabilityCategory,
    EnvironmentPlan,
    EnvironmentReadiness,
    Evidence,
    Finding,
    RiskLevel,
)
from r_sandbox.tools.dependency_analyzer import DependencyAnalyzer
from r_sandbox.tools.source_analyzer import AnalysisLimits
from r_sandbox.tools.source_analyzer import analyzer as source_analyzer_module


ROOT = Path(__file__).resolve().parents[1]


class RepositoryUnderstandingTests(unittest.TestCase):
    def test_finding_id_collision_cannot_overwrite_distinct_semantics(self) -> None:
        critical = Finding(
            "finding-forced-collision",
            CapabilityCategory.NETWORK,
            "send",
            "collector.invalid",
            RiskLevel.CRITICAL,
            "possible exfiltration",
            (Evidence("a.py", "possible exfiltration", 1),),
        )
        benign = Finding(
            "finding-forced-collision",
            CapabilityCategory.FILESYSTEM,
            "read",
            "<repository>",
            RiskLevel.LOW,
            "repository read",
            (Evidence("z.py", "repository read", 1),),
        )
        deduplicated = source_analyzer_module._deduplicate_findings(
            (critical, benign)
        )
        self.assertEqual(len(deduplicated), 2)
        self.assertIn(critical, deduplicated)

    def test_static_network_target_redacts_userinfo_path_and_query(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "train.py").write_text(
                "import requests\n"
                "requests.get('https://user:password@datasets.example.org/private?token=url-secret')\n"
                "requests.get('http://plain.example.org/data')\n"
                "requests.get('https://custom.example.org:8443/data')\n",
                encoding="utf-8",
            )
            profile = RepositoryUnderstanding().analyze(root, "download dataset")
        network_targets = {
            finding.target
            for finding in profile.findings
            if finding.category.value == "network"
        }
        self.assertEqual(
            network_targets,
            {
                "datasets.example.org:443",
                "plain.example.org:80",
                "custom.example.org:8443",
            },
        )
        serialized = json.dumps(asdict(profile))
        self.assertNotIn("password", serialized)
        self.assertNotIn("url-secret", serialized)

    def test_process_and_dependency_secrets_are_absent_from_profile_and_reports(
        self,
    ) -> None:
        secrets = (
            "command-secret",
            "argument-secret",
            "executable-path-secret",
            "notebook-secret",
            "url-password-secret",
            "url-path-secret",
            "url-query-secret",
            "bare-password-secret",
            "bare-path-secret",
            "project-path-secret",
            "malformed-list-secret",
            "poetry-password-secret",
            "poetry-path-secret",
            "poetry-query-secret",
            "poetry-local-path-secret",
            "branch-secret",
            "revision-secret",
            "marker-secret",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "train.py").write_text(
                "import os\n"
                "import subprocess\n"
                "os.system(\"curl --header 'Authorization: command-secret' https://example.invalid\")\n"
                "subprocess.run([\"C:/private/executable-path-secret/python.exe\", "
                "\"--token=argument-secret\"])\n",
                encoding="utf-8",
            )
            (root / "experiment.ipynb").write_text(
                json.dumps(
                    {
                        "cells": [
                            {
                                "cell_type": "code",
                                "source": ["!curl --token notebook-secret example.invalid\n"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (root / "requirements.txt").write_text(
                "privatepkg @ "
                "https://user:url-password-secret@packages.example.org/"
                "private/url-path-secret.whl?token=url-query-secret\n"
                "https://user:bare-password-secret@packages.example.org/"
                "private/bare-path-secret.whl\n",
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text(
                "[project]\n"
                "dependencies = [\n"
                '  "localpkg @ file:///C:/private/project-path-secret.whl",\n'
                '  "%%% malformed-list-secret",\n'
                "]\n"
                "[tool.poetry.dependencies]\n"
                'python = "^3.11"\n'
                'urlpkg = { url = "https://user:poetry-password-secret@'
                'packages.example.org/private/poetry-path-secret.whl?'
                'token=poetry-query-secret", branch = "branch-secret", '
                'markers = "python_version == \'marker-secret\'" }\n'
                'pathpkg = { path = "../poetry-local-path-secret", '
                'rev = "revision-secret" }\n',
                encoding="utf-8",
            )

            profile = RepositoryUnderstanding().analyze(root, "inspect safely")
            report = AgentReport(
                outcome=AgentOutcome.ANALYZED,
                goal="inspect safely",
                repository=str(root),
                profile=profile,
                environment_plan=EnvironmentPlan(
                    runtime="python",
                    image="python:3.11",
                    image_pinned=False,
                    readiness=EnvironmentReadiness.PREBUILT_IMAGE_REQUIRED,
                    dependencies=profile.dependencies,
                ),
            )
            serialized = "\n".join(
                (
                    json.dumps(asdict(profile)),
                    ReportGenerator().json_text(report),
                    ReportGenerator().markdown(report),
                )
            )

        process_targets = {
            finding.target
            for finding in profile.findings
            if finding.category == CapabilityCategory.PROCESS
        }
        self.assertIn("os.system", process_targets)
        self.assertIn("subprocess.run", process_targets)
        self.assertIn("<notebook-shell-command>", process_targets)
        self.assertIn("<remote-reference:packages.example.org>", serialized)
        self.assertIn("<local-path>", serialized)
        self.assertTrue(any("Could not parse dependency" in item for item in profile.warnings))
        for secret in secrets:
            self.assertNotIn(secret, serialized)

    def test_safe_fixture_finds_data_flow_and_entrypoint(self) -> None:
        profile = RepositoryUnderstanding().analyze(
            ROOT / "examples" / "safe_research_repo",
            "reproduce mean",
        )
        self.assertEqual(profile.entrypoints[0].argv, ("python", "train.py"))
        observed = {(item.category, item.action, item.target) for item in profile.findings}
        self.assertIn((CapabilityCategory.FILESYSTEM, "read", "data/sample.csv"), observed)
        self.assertIn((CapabilityCategory.FILESYSTEM, "write", "/output/result.json"), observed)

    def test_gpu_api_reference_is_modeled_as_coarse_device_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "train.py").write_text(
                "import torch\ndevice_api = torch.cuda\n",
                encoding="utf-8",
            )
            profile = RepositoryUnderstanding().analyze(root, "inspect GPU")

        device_findings = [
            finding
            for finding in profile.findings
            if finding.category == CapabilityCategory.DEVICE
        ]
        self.assertTrue(device_findings)
        self.assertTrue(all(finding.action == "access" for finding in device_findings))

    def test_risky_fixture_finds_secret_and_network(self) -> None:
        profile = RepositoryUnderstanding().analyze(
            ROOT / "examples" / "risky_research_repo",
            "run experiment",
        )
        categories = {item.category for item in profile.findings}
        self.assertIn(CapabilityCategory.SECRET, categories)
        self.assertIn(CapabilityCategory.NETWORK, categories)
        self.assertTrue(
            any(item.category == CapabilityCategory.NETWORK and item.action == "send" for item in profile.findings)
        )

    def test_readme_is_evidence_not_a_shell_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                "# Demo\n\n```sh\npython missing.py; dangerous-command\n```\n",
                encoding="utf-8",
            )
            (root / "train.py").write_text(
                "if __name__ == '__main__':\n    print('fixture')\n",
                encoding="utf-8",
            )
            profile = RepositoryUnderstanding().analyze(root, "test")
        self.assertEqual(profile.entrypoints[0].argv, ("python", "train.py"))
        self.assertNotIn("dangerous-command", " ".join(profile.entrypoints[0].argv))

    def test_readme_command_arguments_are_not_retained_or_planned(self) -> None:
        canary = "README_ARGUMENT_SECRET_CANARY"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                f"# Demo\n\n```sh\npython odd.py --token {canary}\n```\n",
                encoding="utf-8",
            )
            (root / "odd.py").write_text("print('fixture')\n", encoding="utf-8")
            profile = RepositoryUnderstanding().analyze(root, "run demo")
            report = AgentReport(
                outcome=AgentOutcome.ANALYZED,
                goal="run demo",
                repository=str(root),
                profile=profile,
            )
            serialized = ReportGenerator().json_text(report)
        self.assertEqual(profile.entrypoints[0].argv, ("python", "odd.py"))
        self.assertNotIn(canary, serialized)

    def test_readme_prose_is_not_copied_into_report_summary(self) -> None:
        canary = "README_PLAINTEXT_SECRET_CANARY"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                f"# Demo\n\nInternal credential: {canary}\n",
                encoding="utf-8",
            )
            (root / "train.py").write_text(
                "if __name__ == '__main__':\n    print('fixture')\n",
                encoding="utf-8",
            )
            profile = RepositoryUnderstanding().analyze(root, "test")
        self.assertIn("README documentation was observed", profile.summary)
        self.assertNotIn(canary, profile.summary)

    def test_directory_count_limit_prunes_wide_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("a", "b", "c"):
                child = root / name
                child.mkdir()
                (child / "main.py").write_text("print('fixture')\n", encoding="utf-8")

            profile = RepositoryUnderstanding(
                limits=AnalysisLimits(max_directories=2)
            ).analyze(root, "test")

        self.assertIn("a/main.py", profile.files)
        self.assertNotIn("b/main.py", profile.files)
        self.assertNotIn("c/main.py", profile.files)
        self.assertTrue(
            any(
                "Directory-count limit reached at 2" in warning
                for warning in profile.warnings
            )
        )

    def test_directory_depth_limit_prunes_deep_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "level-1"
            pruned = allowed / "level-2"
            pruned.mkdir(parents=True)
            (allowed / "allowed.py").write_text("print('allowed')\n", encoding="utf-8")
            (pruned / "pruned.py").write_text("print('pruned')\n", encoding="utf-8")

            profile = RepositoryUnderstanding(
                limits=AnalysisLimits(max_depth=1)
            ).analyze(root, "test")

        self.assertIn("level-1/allowed.py", profile.files)
        self.assertNotIn("level-1/level-2/pruned.py", profile.files)
        self.assertTrue(
            any(
                "Directory-depth limit reached at 1" in warning
                for warning in profile.warnings
            )
        )

    def test_directory_entry_budget_stops_wide_enumeration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(3):
                (root / f"{index}.py").write_text("print('fixture')\n", encoding="utf-8")

            profile = RepositoryUnderstanding(
                limits=AnalysisLimits(max_directory_entries=2)
            ).analyze(root, "test")

        self.assertLessEqual(len(profile.files), 2)
        self.assertTrue(
            any(
                "Directory-entry limit reached at 2" in warning
                for warning in profile.warnings
            )
        )

    def test_ast_node_budget_skips_dense_file_with_coverage_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "train.py").write_text(
                "\n".join(f"value_{index} = {index}" for index in range(100)),
                encoding="utf-8",
            )
            profile = RepositoryUnderstanding(
                limits=AnalysisLimits(max_ast_nodes_per_file=20)
            ).analyze(root, "test")
        self.assertTrue(any("AST node limit reached" in item for item in profile.warnings))

    def test_finding_budget_bounds_dense_security_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "train.py").write_text(
                "\n".join(f"open('file-{index}.txt').read()" for index in range(20)),
                encoding="utf-8",
            )
            profile = RepositoryUnderstanding(
                limits=AnalysisLimits(max_findings=3)
            ).analyze(root, "test")
        self.assertLessEqual(len(profile.findings), 3)
        self.assertTrue(any("Finding" in item and "limit" in item for item in profile.warnings))

    def test_notebook_magic_findings_are_bounded_before_object_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            notebook = {
                "cells": [
                    {
                        "cell_type": "code",
                        "source": [f"!echo line-{index}\n" for index in range(50)],
                    }
                ]
            }
            (root / "experiment.ipynb").write_text(
                json.dumps(notebook), encoding="utf-8"
            )
            profile = RepositoryUnderstanding(
                limits=AnalysisLimits(max_findings=3)
            ).analyze(root, "test")
        self.assertLessEqual(len(profile.findings), 3)
        self.assertTrue(any("notebook magics" in item for item in profile.warnings))

    def test_oversized_json_integer_is_a_notebook_coverage_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "experiment.ipynb").write_text(
                '{"cells":[],"value":' + ("9" * 5000) + "}",
                encoding="utf-8",
            )
            profile = RepositoryUnderstanding().analyze(root, "test")
        self.assertTrue(
            any("parse notebook" in warning.lower() for warning in profile.warnings)
        )

    def test_deeply_nested_notebook_json_is_a_coverage_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = ("[" * 1100) + "0" + ("]" * 1100)
            (root / "experiment.ipynb").write_text(nested, encoding="utf-8")
            profile = RepositoryUnderstanding().analyze(root, "test")
        self.assertTrue(profile.warnings)

    def test_oversized_toml_integer_is_a_dependency_coverage_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text(
                "oversized = " + ("9" * 5000) + "\n",
                encoding="utf-8",
            )
            analysis = DependencyAnalyzer().analyze(root)
        self.assertTrue(
            any("could not parse" in warning.lower() for warning in analysis.warnings)
        )

    def test_deeply_nested_toml_is_a_dependency_coverage_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = ("[" * 1100) + "0" + ("]" * 1100)
            (root / "pyproject.toml").write_text(
                "value = " + nested + "\n", encoding="utf-8"
            )
            analysis = DependencyAnalyzer().analyze(root)
        self.assertTrue(analysis.warnings)

    def test_dependency_and_warning_objects_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text(
                "\n".join(f"package-{index}==1.0" for index in range(20)),
                encoding="utf-8",
            )
            analysis = DependencyAnalyzer(
                max_dependencies=3,
                max_warnings=2,
            ).analyze(root)
        self.assertLessEqual(len(analysis.dependencies), 3)
        self.assertLessEqual(len(analysis.warnings), 2)
        self.assertTrue(any("limit" in item.lower() for item in analysis.warnings))

    def test_unsupported_dependency_metadata_is_a_coverage_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "environment.yml").write_text(
                "dependencies:\n  - python=3.11\n", encoding="utf-8"
            )
            analysis = DependencyAnalyzer().analyze(root)
        self.assertTrue(any("environment.yml" in item for item in analysis.warnings))

    @unittest.skipUnless(os.name == "nt", "Windows junction behavior")
    def test_windows_directory_junction_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "repository"
            target = base / "outside"
            root.mkdir()
            target.mkdir()
            (target / "outside.py").write_text(
                "print('outside')\n", encoding="utf-8"
            )
            junction = root / "junction"
            created = subprocess.run(
                [
                    "cmd.exe",
                    "/d",
                    "/c",
                    "mklink",
                    "/J",
                    str(junction),
                    str(target),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest(f"Could not create directory junction: {created.stderr}")

            try:
                profile = RepositoryUnderstanding().analyze(root, "test")
            finally:
                junction.rmdir()

        self.assertNotIn("junction/outside.py", profile.files)
        self.assertTrue(
            any("reparse-point" in warning for warning in profile.warnings)
        )


if __name__ == "__main__":
    unittest.main()
