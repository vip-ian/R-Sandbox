"""Bounded, deterministic static analysis for untrusted research repositories.

This module deliberately never imports repository modules, invokes a package
manager, or executes a command found in source or documentation.  It treats
every path and every byte in the target repository as untrusted input.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence
from urllib.parse import urlparse

from ...models import (
    CapabilityCategory,
    Entrypoint,
    Evidence,
    Finding,
    RiskLevel,
)


_IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site-packages",
        "venv",
    }
)
_README_NAMES = ("README.md", "README.rst", "README.txt", "README")
_PYTHON_SUFFIXES = frozenset({".py", ".pyw"})
_SOURCE_SUFFIXES = _PYTHON_SUFFIXES | frozenset({".ipynb"})
_CONVENTIONAL_ENTRYPOINTS = {
    "main.py": 0.86,
    "app.py": 0.78,
    "cli.py": 0.78,
    "run.py": 0.76,
    "train.py": 0.72,
    "experiment.py": 0.72,
    "evaluate.py": 0.72,
    "eval.py": 0.70,
    "predict.py": 0.70,
    "infer.py": 0.70,
    "preprocess.py": 0.68,
}
_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|access[_-]?key|secret|token|password|passwd|"
    r"private[_-]?key|credential|auth)(?:$|[_-])",
    re.IGNORECASE,
)
_FENCE = re.compile(r"^\s*```(?P<language>[\w.+-]*)\s*$")
_PYTHON_COMMAND = re.compile(
    r"^\s*(?:\$\s*)?(?:python(?:3(?:\.\d+)?)?|py)(?:\s+-[A-Za-z]+)*\s+"
    r"(?P<target>(?:[^\s]+\.py)|(?:-m\s+[A-Za-z_][\w.]*))(?P<args>.*)$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class AnalysisLimits:
    """Hard limits that bound work performed on an untrusted repository."""

    max_files: int = 5_000
    max_directories: int = 1_000
    max_depth: int = 32
    max_directory_entries: int = 10_000
    max_total_bytes: int = 32 * 1024 * 1024
    max_file_bytes: int = 2 * 1024 * 1024
    max_notebook_cells: int = 1_000
    max_ast_nodes_per_file: int = 50_000
    max_findings: int = 5_000

    def __post_init__(self) -> None:
        for name in (
            "max_files",
            "max_directories",
            "max_depth",
            "max_directory_entries",
            "max_total_bytes",
            "max_file_bytes",
            "max_notebook_cells",
            "max_ast_nodes_per_file",
            "max_findings",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


@dataclass(frozen=True, slots=True)
class SourceAnalysis:
    files: tuple[str, ...]
    findings: tuple[Finding, ...]
    entrypoints: tuple[Entrypoint, ...]
    readme_text: str = ""
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _FileRecord:
    path: Path
    relative: str
    size: int


class SourceAnalyzer:
    """Inspect Python and notebook source using only parsers from the stdlib."""

    def __init__(self, limits: AnalysisLimits | None = None) -> None:
        self.limits = limits or AnalysisLimits()

    def analyze(self, root: str | os.PathLike[str]) -> SourceAnalysis:
        canonical_root = _canonical_root(root)
        records, warnings = self._inventory(canonical_root)
        findings: list[Finding] = []
        entrypoints: list[Entrypoint] = []
        readme_text = ""
        remaining_bytes = self.limits.max_total_bytes

        readme = next(
            (record for name in _README_NAMES for record in records if record.relative == name),
            None,
        )
        if readme is not None:
            text, message, consumed = _read_text_bounded(
                readme, canonical_root, self.limits.max_file_bytes, remaining_bytes
            )
            remaining_bytes -= consumed
            if message:
                warnings.append(message)
            elif text is not None:
                readme_text = text

        for record in records:
            if record.path.suffix.lower() not in _SOURCE_SUFFIXES:
                continue
            text, message, consumed = _read_text_bounded(
                record, canonical_root, self.limits.max_file_bytes, remaining_bytes
            )
            remaining_bytes -= consumed
            if message:
                warnings.append(message)
                if remaining_bytes <= 0:
                    break
                continue
            if text is None:
                continue
            if record.path.suffix.lower() == ".ipynb":
                notebook_findings, notebook_warnings = self._analyze_notebook(
                    record.relative, text
                )
                findings.extend(notebook_findings)
                warnings.extend(notebook_warnings)
            else:
                module_findings, has_main, parse_warning = _analyze_python(
                    record.relative,
                    text,
                    max_ast_nodes=self.limits.max_ast_nodes_per_file,
                    max_findings=max(1, self.limits.max_findings - len(findings)),
                )
                findings.extend(module_findings)
                if parse_warning:
                    warnings.append(parse_warning)
                entrypoint = _source_entrypoint(record.relative, has_main)
                if entrypoint is not None:
                    entrypoints.append(entrypoint)
            if len(findings) >= self.limits.max_findings:
                findings = findings[: self.limits.max_findings]
                warnings.append(
                    f"Finding-count limit reached at {self.limits.max_findings}; "
                    "remaining security observations were skipped."
                )
                break

        if remaining_bytes <= 0:
            warnings.append(
                f"Static-analysis byte budget exhausted at {self.limits.max_total_bytes} bytes."
            )

        existing = frozenset(record.relative for record in records)
        entrypoints.extend(_readme_entrypoints(readme_text, existing))
        return SourceAnalysis(
            files=tuple(record.relative for record in records),
            findings=_deduplicate_findings(findings),
            entrypoints=_deduplicate_entrypoints(entrypoints),
            readme_text=readme_text,
            warnings=tuple(dict.fromkeys(warnings)),
        )

    def _inventory(self, root: Path) -> tuple[list[_FileRecord], list[str]]:
        records: list[_FileRecord] = []
        warnings: list[str] = []
        stopped = False
        file_entries_seen = 0
        directories_scheduled = 1  # The repository root is the first directory.
        directory_entries_seen = 0
        directory_limit_reported = False
        depth_limit_reported = False
        stack: list[tuple[Path, int]] = [(root, 0)]

        while stack and not stopped:
            directory_path, depth = stack.pop()
            relative_directory = _relative_name(root, directory_path) or "."
            try:
                iterator = os.scandir(directory_path)
            except OSError as error:
                warnings.append(f"Could not inspect path {relative_directory}: {error}")
                continue

            entries: list[os.DirEntry[str]] = []
            try:
                with iterator:
                    for entry in iterator:
                        if (
                            directory_entries_seen
                            >= self.limits.max_directory_entries
                        ):
                            warnings.append(
                                "Directory-entry limit reached at "
                                f"{self.limits.max_directory_entries}; remaining paths "
                                "were skipped."
                            )
                            stopped = True
                            break
                        directory_entries_seen += 1
                        entries.append(entry)
            except OSError as error:
                warnings.append(
                    f"Could not enumerate directory {relative_directory}: {error}"
                )
                continue

            child_directories: list[tuple[Path, int]] = []
            for entry in sorted(entries, key=lambda item: item.name):
                name = entry.name
                path = Path(entry.path)
                relative = _relative_name(root, path)
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as error:
                    warnings.append(f"Could not inspect {relative}: {error}")
                    continue
                if _is_symlink(path, metadata):
                    warnings.append(
                        f"Skipped symbolic-link or reparse-point path: {relative}"
                    )
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    if name in _IGNORED_DIRECTORIES:
                        continue
                    if not _contained(root, path):
                        warnings.append(
                            f"Skipped path outside repository root: {relative}"
                        )
                        continue
                    if depth + 1 > self.limits.max_depth:
                        if not depth_limit_reported:
                            warnings.append(
                                "Directory-depth limit reached at "
                                f"{self.limits.max_depth}; deeper directories were "
                                "skipped."
                            )
                            depth_limit_reported = True
                        continue
                    if directories_scheduled >= self.limits.max_directories:
                        if not directory_limit_reported:
                            warnings.append(
                                "Directory-count limit reached at "
                                f"{self.limits.max_directories}; remaining directories "
                                "were skipped."
                            )
                            directory_limit_reported = True
                        continue
                    directories_scheduled += 1
                    child_directories.append((path, depth + 1))
                    continue
                if file_entries_seen >= self.limits.max_files:
                    warnings.append(
                        f"File-count limit reached at {self.limits.max_files}; remaining files were skipped."
                    )
                    stopped = True
                    break
                # Special files count too. Symbolic links and reparse points
                # are already bounded by the global directory-entry budget.
                file_entries_seen += 1
                if not stat.S_ISREG(metadata.st_mode):
                    warnings.append(f"Skipped non-regular file: {relative}")
                    continue
                if not _contained(root, path):
                    warnings.append(f"Skipped path outside repository root: {relative}")
                    continue
                records.append(_FileRecord(path, relative, metadata.st_size))
            if stopped:
                break
            # Reversing preserves deterministic, lexicographic depth-first
            # traversal while keeping the stack bounded.
            stack.extend(reversed(child_directories))

        records.sort(key=lambda record: record.relative)
        return records, warnings

    def _analyze_notebook(
        self, source: str, text: str
    ) -> tuple[list[Finding], list[str]]:
        try:
            notebook = json.loads(text)
        except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError) as error:
            return [], [f"Could not parse notebook {source}: {error}"]
        if not isinstance(notebook, dict) or not isinstance(notebook.get("cells"), list):
            return [], [f"Notebook {source} has no valid cells array."]

        findings: list[Finding] = []
        warnings: list[str] = []
        code_cells = 0
        for cell_index, cell in enumerate(notebook["cells"], start=1):
            if not isinstance(cell, dict) or cell.get("cell_type") != "code":
                continue
            code_cells += 1
            if code_cells > self.limits.max_notebook_cells:
                warnings.append(
                    f"Notebook cell limit reached in {source} at "
                    f"{self.limits.max_notebook_cells} code cells."
                )
                break
            raw_source = cell.get("source", "")
            if isinstance(raw_source, list):
                code = "".join(part for part in raw_source if isinstance(part, str))
            elif isinstance(raw_source, str):
                code = raw_source
            else:
                warnings.append(f"Skipped malformed code cell {cell_index} in {source}.")
                continue
            cell_source = f"{source}#cell-{cell_index}"
            remaining_findings = max(1, self.limits.max_findings - len(findings))
            code, magic_findings, magic_truncated = _sanitize_notebook_code(
                cell_source,
                code,
                max_findings=remaining_findings,
            )
            findings.extend(magic_findings)
            if magic_truncated:
                warnings.append(
                    f"Finding limit reached while analyzing notebook magics in {source}."
                )
                break
            if len(findings) >= self.limits.max_findings:
                warnings.append(
                    f"Finding-count limit reached in {source} at "
                    f"{self.limits.max_findings} findings."
                )
                break
            cell_findings, _, parse_warning = _analyze_python(
                cell_source,
                code,
                max_ast_nodes=self.limits.max_ast_nodes_per_file,
                max_findings=max(1, self.limits.max_findings - len(findings)),
            )
            findings.extend(cell_findings)
            if parse_warning:
                warnings.append(parse_warning)
        return findings, warnings


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, source: str, max_findings: int) -> None:
        self.source = source
        self.max_findings = max_findings
        self.aliases: dict[str, str] = {}
        self.findings: list[Finding] = []
        self.has_main_guard = False
        self.truncated = False

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            bound = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[bound] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        if _is_main_guard(node.test):
            self.has_main_guard = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        raw_name = _dotted_name(node.func)
        name = self._resolve(raw_name)
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        target = _literal_text(node.args[0]) if node.args else "<dynamic>"
        receiver_target = _receiver_literal(node.func)

        if name in {"open", "io.open", "pathlib.Path.open"} or name.endswith(".open"):
            mode = _call_mode(node)
            action = "write" if any(flag in mode for flag in "wax+") else "read"
            if receiver_target != "<dynamic>":
                target = receiver_target
            self._add(
                CapabilityCategory.FILESYSTEM,
                action,
                target,
                RiskLevel.MEDIUM if action == "write" else RiskLevel.LOW,
                f"File {action} through {name or '<dynamic>.open'} (mode={mode!r}).",
                node,
            )
        elif method in {"read_text", "read_bytes"}:
            self._add(
                CapabilityCategory.FILESYSTEM,
                "read",
                receiver_target,
                RiskLevel.LOW,
                f"File read through {name}.",
                node,
            )
        elif method in {"write_text", "write_bytes", "touch", "mkdir"}:
            self._add(
                CapabilityCategory.FILESYSTEM,
                "write",
                receiver_target,
                RiskLevel.MEDIUM,
                f"File-system mutation through {name}.",
                node,
            )
        elif method in {"unlink", "rmdir", "rename", "replace"}:
            self._add(
                CapabilityCategory.FILESYSTEM,
                "delete_or_move",
                receiver_target,
                RiskLevel.HIGH,
                f"Destructive file-system operation through {name}.",
                node,
            )
        elif name in {
            "os.remove",
            "os.unlink",
            "os.rmdir",
            "os.removedirs",
            "os.rename",
            "os.replace",
            "shutil.move",
            "shutil.rmtree",
        }:
            self._add(
                CapabilityCategory.FILESYSTEM,
                "delete_or_move",
                target,
                RiskLevel.HIGH,
                f"Destructive file-system operation through {name}.",
                node,
            )
        elif name in {
            "os.mkdir",
            "os.makedirs",
            "shutil.copy",
            "shutil.copy2",
            "shutil.copyfile",
            "shutil.copytree",
        }:
            self._add(
                CapabilityCategory.FILESYSTEM,
                "write",
                target,
                RiskLevel.MEDIUM,
                f"File-system write through {name}.",
                node,
            )

        if _is_network_call(name):
            network_action = _network_action(name, node)
            self._add(
                CapabilityCategory.NETWORK,
                network_action,
                _redacted_network_target(target),
                RiskLevel.CRITICAL if network_action == "send" else RiskLevel.HIGH,
                (
                    f"Potential outbound data transfer through {name}."
                    if network_action == "send"
                    else f"Potential network operation through {name}."
                ),
                node,
            )

        if _is_process_call(name):
            self._add(
                CapabilityCategory.PROCESS,
                "spawn",
                _redacted_process_target(name),
                RiskLevel.HIGH,
                f"Child-process or shell execution through {name}.",
                node,
            )

        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self._add(
                CapabilityCategory.SIDE_EFFECT,
                "dynamic_code",
                name.rsplit(".", 1)[-1],
                RiskLevel.CRITICAL,
                f"Dynamic code execution through {name}.",
                node,
            )

        if name in {"os.getenv", "os.environ.get", "os.environ.setdefault"}:
            self._add_environment(target, node)

        if _is_device_call(name, node):
            self._add(
                CapabilityCategory.DEVICE,
                "access",
                _device_target(name, node),
                RiskLevel.HIGH,
                f"Potential host-device access through {name}.",
                node,
            )
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
        name = self._resolve(_dotted_name(node.value))
        if name == "os.environ":
            self._add_environment(_literal_text(node.slice), node)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        name = self._resolve(_dotted_name(node))
        if name.startswith(("torch.cuda", "tensorflow.config.list_physical_devices")):
            self._add(
                CapabilityCategory.DEVICE,
                "access",
                "gpu",
                RiskLevel.MEDIUM,
                f"GPU/device API referenced through {name}.",
                node,
            )
        self.generic_visit(node)

    def _resolve(self, name: str) -> str:
        if not name:
            return ""
        first, separator, rest = name.partition(".")
        base = self.aliases.get(first, first)
        return base + (separator + rest if separator else "")

    def _add_environment(self, key: str, node: ast.AST) -> None:
        secret_like = key != "<dynamic>" and bool(_SECRET_KEY.search(key))
        self._add(
            CapabilityCategory.SECRET,
            "read_environment",
            f"env:{key}",
            RiskLevel.HIGH if secret_like or key == "<dynamic>" else RiskLevel.MEDIUM,
            "Environment-variable access; key appears secret-like."
            if secret_like
            else "Environment-variable access (value may be sensitive).",
            node,
        )

    def _add(
        self,
        category: CapabilityCategory,
        action: str,
        target: str,
        risk: RiskLevel,
        reason: str,
        node: ast.AST,
    ) -> None:
        if len(self.findings) >= self.max_findings:
            self.truncated = True
            return
        line = getattr(node, "lineno", None)
        normalized_target = target or "<dynamic>"
        evidence = Evidence(
            source=self.source,
            detail=reason,
            line=line if isinstance(line, int) else None,
        )
        self.findings.append(
            Finding(
                finding_id=_finding_id(
                    self.source,
                    line if isinstance(line, int) else None,
                    category,
                    action,
                    normalized_target,
                    risk,
                    reason,
                ),
                category=category,
                action=action,
                target=normalized_target,
                risk=risk,
                reason=reason,
                evidence=(evidence,),
            )
        )


def _canonical_root(root: str | os.PathLike[str]) -> Path:
    candidate = Path(root)
    try:
        canonical = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"Repository root is not accessible: {candidate}") from error
    if not canonical.is_dir():
        raise ValueError(f"Repository root is not a directory: {canonical}")
    return canonical


def _relative_name(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _contained(root: Path, path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root)
    except (OSError, ValueError):
        return False
    return True


def _is_symlink(path: Path, metadata: os.stat_result | None = None) -> bool:
    """Fail closed for symbolic links and Windows reparse-point directories."""

    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        current = metadata if metadata is not None else path.lstat()
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return bool(getattr(current, "st_file_attributes", 0) & reparse_flag)
    except OSError:
        return True


def _read_text_bounded(
    record: _FileRecord,
    root: Path,
    per_file_limit: int,
    remaining_budget: int,
) -> tuple[str | None, str | None, int]:
    if record.size > per_file_limit:
        return None, f"Skipped oversized file {record.relative} ({record.size} bytes).", 0
    if record.size > remaining_budget:
        return None, f"Skipped {record.relative}: total byte budget would be exceeded.", 0
    if _is_symlink(record.path) or not _contained(root, record.path):
        return None, f"Skipped unsafe path after inventory: {record.relative}", 0
    try:
        with record.path.open("rb") as handle:
            data = handle.read(per_file_limit + 1)
    except OSError as error:
        return None, f"Could not read {record.relative}: {error}", 0
    if len(data) > per_file_limit:
        return None, f"Skipped file that grew beyond limit: {record.relative}", 0
    try:
        return data.decode("utf-8-sig"), None, len(data)
    except UnicodeDecodeError:
        return None, f"Skipped non-UTF-8 source file: {record.relative}", len(data)


def _analyze_python(
    source: str,
    text: str,
    *,
    max_ast_nodes: int,
    max_findings: int,
) -> tuple[list[Finding], bool, str | None]:
    try:
        tree = ast.parse(text, filename=source)
    except (SyntaxError, ValueError, TypeError, RecursionError) as error:
        return [], False, f"Could not parse Python source {source}: {error}"
    for count, _node in enumerate(ast.walk(tree), start=1):
        if count > max_ast_nodes:
            return (
                [],
                False,
                f"AST node limit reached in {source} at {max_ast_nodes}; file was skipped.",
            )
    visitor = _PythonVisitor(source, max_findings=max_findings)
    try:
        visitor.visit(tree)
    except RecursionError:
        return (
            visitor.findings,
            visitor.has_main_guard,
            f"AST traversal recursion limit reached in {source}; analysis is incomplete.",
        )
    warning = (
        f"Finding limit reached while analyzing {source}; remaining observations were skipped."
        if visitor.truncated
        else None
    )
    return visitor.findings, visitor.has_main_guard, warning


def _sanitize_notebook_code(
    source: str,
    code: str,
    *,
    max_findings: int,
) -> tuple[str, list[Finding], bool]:
    """Remove notebook magics while preserving source line numbers.

    Shell escapes are themselves security evidence.  They are reported as
    process findings, but are never interpreted or executed.
    """

    sanitized: list[str] = []
    findings: list[Finding] = []
    shell_cell = False
    shell_cell_prefixes = ("%%bash", "%%sh", "%%script", "%%cmd", "%%powershell")
    for line_number, line in enumerate(code.splitlines(keepends=True), start=1):
        stripped = line.lstrip()
        if line_number == 1 and stripped.lower().startswith(shell_cell_prefixes):
            shell_cell = True
        magic = shell_cell or stripped.startswith(("%", "!", "?"))
        if magic:
            process_magic = (
                shell_cell
                or stripped.startswith("!")
                or stripped.lower().startswith(("%pip", "%conda"))
            )
            if process_magic and (not shell_cell or line_number == 1):
                if len(findings) >= max_findings:
                    return "".join(sanitized), findings, True
                detail = "Notebook shell or installer magic may spawn a process."
                findings.append(
                    Finding(
                        finding_id=_finding_id(
                            source,
                            line_number,
                            CapabilityCategory.PROCESS,
                            "spawn",
                            _redacted_notebook_process_target(stripped, shell_cell),
                            RiskLevel.HIGH,
                            detail,
                        ),
                        category=CapabilityCategory.PROCESS,
                        action="spawn",
                        target=_redacted_notebook_process_target(stripped, shell_cell),
                        risk=RiskLevel.HIGH,
                        reason=detail,
                        evidence=(Evidence(source=source, detail=detail, line=line_number),),
                    )
                )
            sanitized.append("\n" if line.endswith(("\n", "\r")) else "")
        else:
            sanitized.append(line)
    return "".join(sanitized), findings, False


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _literal_text(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float)):
        return str(node.value)
    if isinstance(node, (ast.List, ast.Tuple)):
        values = [_literal_text(item) for item in node.elts]
        if all(value != "<dynamic>" for value in values):
            return " ".join(values)
    return "<dynamic>"


def _receiver_literal(function: ast.AST) -> str:
    if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Call):
        call = function.value
        if _dotted_name(call.func) in {"Path", "pathlib.Path"} and call.args:
            return _literal_text(call.args[0])
    return "<dynamic>"


def _call_mode(node: ast.Call) -> str:
    if len(node.args) > 1:
        candidate = _literal_text(node.args[1])
        if candidate != "<dynamic>":
            return candidate
    for keyword in node.keywords:
        if keyword.arg == "mode":
            candidate = _literal_text(keyword.value)
            if candidate != "<dynamic>":
                return candidate
    return "r"


def _is_main_guard(node: ast.AST) -> bool:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return False
    if not isinstance(node.ops[0], (ast.Eq, ast.Is)):
        return False
    pairs = ((node.left, node.comparators[0]), (node.comparators[0], node.left))
    return any(
        isinstance(left, ast.Name)
        and left.id == "__name__"
        and isinstance(right, ast.Constant)
        and right.value == "__main__"
        for left, right in pairs
    )


def _is_network_call(name: str) -> bool:
    if name.startswith("requests."):
        return name.rsplit(".", 1)[-1] in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "options",
            "request",
            "Session",
        }
    return name in {
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "urllib.request.Request",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "socket.socket",
        "socket.create_connection",
        "socket.getaddrinfo",
    }


def _redacted_network_target(value: str) -> str:
    """Retain only endpoint identity; never persist URL userinfo/query/path."""

    if value in {"", "<dynamic>"}:
        return "<dynamic>"
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        return "<invalid-network-target>"
    if not host:
        return "<dynamic>"
    if port is None:
        if parsed.scheme.lower() == "https":
            port = 443
        elif parsed.scheme.lower() == "http":
            port = 80
    return f"{host}:{port}" if port is not None else host


def _network_action(name: str, node: ast.Call) -> str:
    """Separate expected downloads from uploads and opaque socket access."""

    lowered = name.lower()
    if lowered.startswith("requests."):
        method = lowered.rsplit(".", 1)[-1]
        if method in {"post", "put", "patch", "delete"}:
            return "send"
        if method in {"get", "head", "options"}:
            return "connect_unknown" if _call_carries_outbound_data(node) else "download"
        if method == "request":
            candidate = _literal_text(node.args[0]).lower() if node.args else ""
            for keyword in node.keywords:
                if keyword.arg == "method":
                    candidate = _literal_text(keyword.value).lower()
            return "send" if candidate in {"post", "put", "patch", "delete"} else "connect_unknown"
    if lowered == "urllib.request.request":
        method = ""
        has_data = len(node.args) > 1 and not _is_none_or_empty_literal(node.args[1])
        has_headers = len(node.args) > 2 and not _is_empty_mapping_literal(node.args[2])
        for keyword in node.keywords:
            if keyword.arg == "method":
                method = _literal_text(keyword.value).lower()
            elif keyword.arg == "data":
                has_data = not _is_none_or_empty_literal(keyword.value)
            elif keyword.arg in {"headers", "auth", "cookies"}:
                has_headers = not _is_empty_mapping_literal(keyword.value)
        if has_data or method in {"post", "put", "patch", "delete"}:
            return "send"
        return "connect_unknown" if has_headers or _call_url_has_query(node) else "download"
    if lowered in {"urllib.request.urlretrieve"}:
        return "connect_unknown" if _call_url_has_query(node) else "download"
    if lowered == "urllib.request.urlopen":
        has_data = len(node.args) > 1 or any(
            keyword.arg == "data" for keyword in node.keywords
        )
        return "send" if has_data else "connect_unknown"
    return "connect_unknown"


def _call_carries_outbound_data(node: ast.Call) -> bool:
    if _call_url_has_query(node):
        return True
    return any(
        keyword.arg in {"auth", "cookies", "data", "files", "headers", "json", "params"}
        and not _is_none_or_empty_literal(keyword.value)
        and not _is_empty_mapping_literal(keyword.value)
        for keyword in node.keywords
    )


def _call_url_has_query(node: ast.Call) -> bool:
    if not node.args:
        return True
    value = node.args[0]
    return not isinstance(value, ast.Constant) or not isinstance(value.value, str) or "?" in value.value


def _is_none_or_empty_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value in {None, "", b""}


def _is_empty_mapping_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Dict) and not node.keys


def _is_process_call(name: str) -> bool:
    if name in {
        "os.system",
        "os.popen",
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }:
        return True
    return name.startswith(("os.spawn", "os.exec"))


def _redacted_process_target(name: str) -> str:
    """Identify the process API without retaining any command or argument text."""

    return name or "<child-process>"


def _redacted_notebook_process_target(line: str, shell_cell: bool) -> str:
    """Classify a notebook process escape without retaining its command payload."""

    if shell_cell:
        return "<notebook-shell-cell>"
    lowered = line.lstrip().lower()
    if lowered.startswith(("%pip", "%conda")):
        return "<notebook-installer-magic>"
    return "<notebook-shell-command>"


def _is_device_call(name: str, node: ast.Call) -> bool:
    if name in {"serial.Serial", "torch.device"}:
        return True
    if name.startswith("torch.cuda."):
        return True
    method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
    if method in {"to", "device"} and node.args:
        target = _literal_text(node.args[0]).lower()
        return target.startswith(("cuda", "mps", "xpu"))
    return any(
        _literal_text(argument).startswith(("/dev/", "\\\\.\\"))
        for argument in node.args
    )


def _device_target(name: str, node: ast.Call) -> str:
    for argument in node.args:
        value = _literal_text(argument)
        if value != "<dynamic>" and (
            value.lower().startswith(("cuda", "mps", "xpu"))
            or value.startswith(("/dev/", "\\\\.\\"))
        ):
            return value
    if name.startswith("torch.cuda"):
        return "gpu"
    return "<dynamic-device>"


def _source_entrypoint(relative: str, has_main_guard: bool) -> Entrypoint | None:
    path = Path(relative)
    if path.name == "__main__.py":
        module_parts = path.with_suffix("").parts[:-1]
        if module_parts and all(part.isidentifier() for part in module_parts):
            module = ".".join(module_parts)
            return Entrypoint(
                path=relative,
                argv=("python", "-m", module),
                confidence=0.95,
                evidence="Package __main__.py discovered by static structure analysis.",
            )
    confidence = _CONVENTIONAL_ENTRYPOINTS.get(path.name.lower())
    if has_main_guard:
        confidence = max(confidence or 0.0, 0.9)
    if confidence:
        evidence = (
            "Python __main__ guard discovered by AST analysis."
            if has_main_guard
            else f"Conventional entrypoint filename {path.name!r}."
        )
        return Entrypoint(
            path=relative,
            argv=("python", relative),
            confidence=confidence,
            evidence=evidence,
        )
    return None


def _readme_entrypoints(text: str, existing: frozenset[str]) -> list[Entrypoint]:
    if not text:
        return []
    candidates: list[Entrypoint] = []
    inside_fence = False
    for line in text.splitlines():
        fence = _FENCE.match(line)
        if fence:
            inside_fence = not inside_fence
            continue
        if not inside_fence:
            continue
        match = _PYTHON_COMMAND.match(line)
        if not match:
            continue
        raw_target = match.group("target")
        if raw_target.startswith("-m "):
            module = raw_target[3:].strip()
            module_path = module.replace(".", "/")
            possible = (f"{module_path}.py", f"{module_path}/__main__.py")
            matched_path = next((path for path in possible if path in existing), None)
            if matched_path:
                candidates.append(
                    Entrypoint(
                        path=matched_path,
                        argv=("python", "-m", module),
                        confidence=0.52,
                        evidence=(
                            "Untrusted README command references this existing module; "
                            "recorded as evidence only and never executed during analysis."
                        ),
                    )
                )
            continue
        normalized = raw_target.replace("\\", "/").lstrip("./")
        if normalized in existing and not normalized.startswith("../"):
            candidates.append(
                Entrypoint(
                    path=normalized,
                    argv=("python", normalized),
                    confidence=0.5,
                    evidence=(
                        "Untrusted README command references this existing file; recorded "
                        "as evidence only and never executed during analysis."
                    ),
                )
            )
    return candidates


def _finding_id(
    source: str,
    line: int | None,
    category: CapabilityCategory,
    action: str,
    target: str,
    risk: RiskLevel,
    reason: str,
) -> str:
    fields = (
        source.encode("utf-8", errors="surrogatepass"),
        str(line or 0).encode("ascii"),
        category.value.encode("ascii"),
        action.encode("utf-8", errors="surrogatepass"),
        target.encode("utf-8", errors="surrogatepass"),
        risk.value.encode("ascii"),
        reason.encode("utf-8", errors="surrogatepass"),
    )
    digest = hashlib.sha256()
    for field in fields:
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)
    return f"finding-{digest.hexdigest()[:32]}"


def _deduplicate_findings(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    unique = {
        (
            finding.category,
            finding.action,
            finding.target,
            finding.risk,
            finding.reason,
            tuple(
                (evidence.source, evidence.detail, evidence.line)
                for evidence in finding.evidence
            ),
        ): finding
        for finding in findings
    }
    return tuple(
        unique[key]
        for key in sorted(
            unique,
            key=lambda item: (
                unique[item].evidence[0].source if unique[item].evidence else "",
                unique[item].evidence[0].line or 0 if unique[item].evidence else 0,
                unique[item].category.value,
                unique[item].action,
                unique[item].target,
                unique[item].risk.value,
                unique[item].reason,
            ),
        )
    )


def _deduplicate_entrypoints(
    entrypoints: Sequence[Entrypoint],
) -> tuple[Entrypoint, ...]:
    selected: dict[tuple[str, tuple[str, ...]], Entrypoint] = {}
    for entrypoint in entrypoints:
        key = (entrypoint.path, entrypoint.argv)
        current = selected.get(key)
        if current is None or entrypoint.confidence > current.confidence:
            selected[key] = entrypoint
    return tuple(
        sorted(
            selected.values(),
            key=lambda item: (-item.confidence, item.path, item.argv),
        )
    )
