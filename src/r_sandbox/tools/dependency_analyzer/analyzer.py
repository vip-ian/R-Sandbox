"""Parse dependency declarations without invoking installers or project code."""

from __future__ import annotations

import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from ...models import Dependency


_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$")
_DIRECT_REFERENCE_PREFIX = re.compile(
    r"^(?:(?:git|hg|svn|bzr)\+)?[A-Za-z][A-Za-z0-9+.-]*://",
    re.IGNORECASE,
)
_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:[\\/]")
_SAFE_EXTRAS = re.compile(r"^\[[A-Za-z0-9._,-]+\]$")
_REQUIREMENT_FILES = ("requirements.txt",)
_UNSUPPORTED_DEPENDENCY_FILES = (
    "requirements-dev.txt",
    "requirements-test.txt",
    "setup.py",
    "setup.cfg",
    "environment.yml",
    "environment.yaml",
    "Pipfile",
)


@dataclass(frozen=True, slots=True)
class DependencyAnalysis:
    dependencies: tuple[Dependency, ...]
    warnings: tuple[str, ...] = ()


class DependencyAnalyzer:
    """Extract PEP 508-ish declarations from known metadata files only."""

    def __init__(
        self,
        max_file_bytes: int = 2 * 1024 * 1024,
        *,
        max_dependencies: int = 5_000,
        max_warnings: int = 500,
    ) -> None:
        if max_file_bytes <= 0 or max_dependencies <= 0 or max_warnings <= 0:
            raise ValueError("dependency analysis limits must be positive")
        self.max_file_bytes = max_file_bytes
        self.max_dependencies = max_dependencies
        self.max_warnings = max_warnings

    def analyze(self, root: str | os.PathLike[str]) -> DependencyAnalysis:
        canonical_root = _canonical_root(root)
        dependencies: list[Dependency] = []
        warnings: list[str] = []
        for name in _REQUIREMENT_FILES:
            text, warning = self._read_known_file(canonical_root, name)
            if warning:
                warnings.append(warning)
            if text is not None:
                parsed, parsed_warnings = _parse_requirements(
                    text,
                    name,
                    max_dependencies=self.max_dependencies - len(dependencies),
                    max_warnings=self.max_warnings - len(warnings),
                )
                _extend_bounded(dependencies, parsed, self.max_dependencies)
                _extend_bounded(warnings, parsed_warnings, self.max_warnings)

        pyproject, warning = self._read_known_file(canonical_root, "pyproject.toml")
        if warning:
            warnings.append(warning)
        if pyproject is not None:
            parsed, parsed_warnings = _parse_pyproject(
                pyproject,
                "pyproject.toml",
                max_dependencies=max(1, self.max_dependencies - len(dependencies)),
                max_warnings=max(1, self.max_warnings - len(warnings)),
            )
            _extend_bounded(dependencies, parsed, self.max_dependencies)
            _extend_bounded(warnings, parsed_warnings, self.max_warnings)

        for name in _UNSUPPORTED_DEPENDENCY_FILES:
            path = canonical_root / name
            try:
                exists = path.exists()
            except OSError:
                exists = True
            if exists:
                _append_bounded(
                    warnings,
                    f"Unsupported dependency metadata {name} was not analyzed.",
                    self.max_warnings,
                )

        return DependencyAnalysis(
            dependencies=_deduplicate(dependencies),
            warnings=tuple(dict.fromkeys(warnings)),
        )

    def _read_known_file(self, root: Path, relative: str) -> tuple[str | None, str | None]:
        path = root / relative
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return None, None
        except OSError as error:
            return None, f"Could not inspect {relative}: {error}"
        if _is_link_or_reparse(path, metadata):
            return None, f"Skipped link, junction, or reparse dependency file: {relative}"
        if not path.is_file() or not _contained(root, path):
            return None, f"Skipped unsafe dependency path: {relative}"
        if metadata.st_size > self.max_file_bytes:
            return None, f"Skipped oversized dependency file {relative}."
        descriptor: int | None = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            actual = os.fstat(descriptor)
            if not stat.S_ISREG(actual.st_mode):
                return None, f"Skipped non-regular dependency file: {relative}"
            if (actual.st_dev, actual.st_ino) != (metadata.st_dev, metadata.st_ino):
                return None, f"Skipped dependency file changed before read: {relative}"
            data = os.read(descriptor, self.max_file_bytes + 1)
            final = os.fstat(descriptor)
            if (final.st_size, final.st_mtime_ns) != (actual.st_size, actual.st_mtime_ns):
                return None, f"Skipped dependency file changed during read: {relative}"
            if not _contained(root, path):
                return None, f"Skipped dependency file escaped root during read: {relative}"
        except OSError as error:
            return None, f"Could not read {relative}: {error}"
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if len(data) > self.max_file_bytes:
            return None, f"Skipped dependency file that grew beyond limit: {relative}"
        try:
            return data.decode("utf-8-sig"), None
        except UnicodeDecodeError:
            return None, f"Skipped non-UTF-8 dependency file: {relative}"


def _canonical_root(root: str | os.PathLike[str]) -> Path:
    candidate = Path(root)
    try:
        canonical = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"Repository root is not accessible: {candidate}") from error
    if not canonical.is_dir():
        raise ValueError(f"Repository root is not a directory: {canonical}")
    return canonical


def _contained(root: Path, path: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False
    return True


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


def _parse_requirements(
    text: str,
    source: str,
    *,
    max_dependencies: int = 5_000,
    max_warnings: int = 500,
) -> tuple[list[Dependency], list[str]]:
    dependencies: list[Dependency] = []
    warnings: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if len(dependencies) >= max_dependencies:
            _append_bounded(
                warnings,
                f"Dependency-count limit reached at {max_dependencies} while parsing {source}.",
                max_warnings,
            )
            break
        if len(warnings) >= max_warnings:
            break
        line = _strip_inline_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            _append_bounded(
                warnings,
                f"Ignored nested requirement reference at {source}:{line_number}; "
                "dependency analysis never follows arbitrary paths.",
                max_warnings,
            )
            continue
        if line.startswith(("-e", "--editable", "--")):
            _append_bounded(
                warnings,
                f"Ignored installer option at {source}:{line_number}.",
                max_warnings,
            )
            continue
        dependency = _parse_requirement(line, f"{source}:{line_number}")
        if dependency is None:
            _append_bounded(
                warnings,
                f"Could not parse dependency at {source}:{line_number}.",
                max_warnings,
            )
        else:
            dependencies.append(dependency)
    return dependencies, warnings


def _strip_inline_comment(line: str) -> str:
    # URL fragments are valid requirement content, so only whitespace-prefixed
    # comments are removed.
    return re.split(r"\s+#", line, maxsplit=1)[0]


def _parse_requirement(value: str, source: str) -> Dependency | None:
    stripped = value.strip()
    if _looks_like_dependency_reference(stripped):
        return Dependency(
            name="<direct-reference>",
            specifier=_redacted_dependency_reference(stripped),
            source=source,
        )
    match = _NAME.match(stripped)
    if not match:
        return None
    name, remainder = match.groups()
    return Dependency(
        name=name,
        specifier=_redacted_requirement_specifier(remainder),
        source=source,
    )


def _redacted_requirement_specifier(value: str) -> str:
    """Retain version shape while removing direct-reference and marker values."""

    declaration, separator, _marker = value.strip().partition(";")
    declaration = declaration.strip()
    marker = "; <redacted-marker>" if separator else ""
    if not declaration:
        return marker

    if "@" in declaration:
        prefix, reference = declaration.split("@", 1)
        prefix = prefix.strip()
        safe_prefix = prefix if _SAFE_EXTRAS.fullmatch(prefix) else ""
        redacted = _redacted_dependency_reference(reference)
        declaration = f"{safe_prefix} @ {redacted}".strip()
    elif _looks_like_dependency_reference(declaration) or any(
        marker in declaration for marker in ("/", "\\")
    ):
        declaration = _redacted_dependency_reference(declaration)
    else:
        declaration = " ".join(declaration.split())[:500]

    return f"{declaration} {marker}".strip()


def _looks_like_dependency_reference(value: str) -> bool:
    stripped = value.strip()
    return bool(
        _DIRECT_REFERENCE_PREFIX.match(stripped)
        or _WINDOWS_ABSOLUTE_PATH.match(stripped)
        or stripped.startswith(("/", "./", "../", "\\"))
        or re.match(r"^(?:[^@\s/\\]+@)?[^:\s/\\]+:.+", stripped)
    )


def _redacted_dependency_reference(value: str) -> str:
    """Describe a direct dependency reference without its credentials or path."""

    stripped = value.strip()
    parse_value = stripped
    vcs_match = re.match(r"^(?:git|hg|svn|bzr)\+(.+)$", parse_value, re.IGNORECASE)
    if vcs_match:
        parse_value = vcs_match.group(1)
    try:
        parsed = urlsplit(parse_value)
        scheme = parsed.scheme.lower()
        if scheme == "file":
            return "<local-path>"
        host = parsed.hostname
        port = parsed.port
    except (TypeError, UnicodeError, ValueError):
        return "<redacted-reference>"
    if host:
        endpoint = f"{host}:{port}" if port is not None else host
        return f"<remote-reference:{endpoint}>"

    scp_match = re.match(
        r"^(?:[^@\s/\\]+@)?(?P<host>[^:\s/\\]+):.+",
        parse_value,
    )
    if scp_match and not _WINDOWS_ABSOLUTE_PATH.match(parse_value):
        return f"<remote-reference:{scp_match.group('host')}>"
    return "<local-or-opaque-reference>"


def _parse_pyproject(
    text: str,
    source: str,
    *,
    max_dependencies: int = 5_000,
    max_warnings: int = 500,
) -> tuple[list[Dependency], list[str]]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError) as error:
        return [], [f"Could not parse {source}: {error}"]
    dependencies: list[Dependency] = []
    warnings: list[str] = []

    def add_list(value: Any, label: str) -> None:
        remaining = max_dependencies - len(dependencies)
        if remaining <= 0:
            _append_bounded(
                warnings,
                f"Dependency-count limit reached at {max_dependencies} while parsing {source}.",
                max_warnings,
            )
            return
        dependencies.extend(
            _parse_dependency_list(
                value,
                label,
                warnings,
                max_items=remaining,
                max_warnings=max_warnings,
            )
        )

    project = _mapping(data.get("project"))
    add_list(project.get("dependencies"), f"{source}:[project.dependencies]")
    optional = _mapping(project.get("optional-dependencies"))
    for index, group in enumerate(sorted(optional)):
        if index >= 1_000 or len(dependencies) >= max_dependencies:
            _append_bounded(
                warnings,
                "Optional dependency-group traversal limit reached.",
                max_warnings,
            )
            break
        add_list(
            optional[group],
            f"{source}:[project.optional-dependencies]",
        )

    build_system = _mapping(data.get("build-system"))
    add_list(
        build_system.get("requires"),
        f"{source}:[build-system.requires]",
    )

    groups = _mapping(data.get("dependency-groups"))
    for index, group in enumerate(sorted(groups)):
        if index >= 1_000 or len(dependencies) >= max_dependencies:
            _append_bounded(
                warnings,
                "Dependency-group traversal limit reached.",
                max_warnings,
            )
            break
        add_list(
            groups[group],
            f"{source}:[dependency-groups]",
        )

    tool = _mapping(data.get("tool"))
    poetry = _mapping(_mapping(tool.get("poetry")).get("dependencies"))
    for name in sorted(poetry):
        if len(dependencies) >= max_dependencies:
            _append_bounded(
                warnings,
                f"Dependency-count limit reached at {max_dependencies} while parsing {source}.",
                max_warnings,
            )
            break
        if name.lower() == "python":
            continue
        value = poetry[name]
        if isinstance(value, str):
            specifier = _redacted_requirement_specifier(value)
        elif isinstance(value, dict):
            specifier = _poetry_table_specifier(value)
        else:
            _append_bounded(
                warnings,
                f"Ignored malformed Poetry dependency in {source}.",
                max_warnings,
            )
            continue
        dependencies.append(
            Dependency(
                name=name,
                specifier=specifier,
                source=f"{source}:[tool.poetry.dependencies]",
            )
        )
    return dependencies, warnings


def _parse_dependency_list(
    value: Any,
    source: str,
    warnings: list[str],
    *,
    max_items: int,
    max_warnings: int,
) -> list[Dependency]:
    if value is None:
        return []
    if not isinstance(value, list):
        _append_bounded(
            warnings, f"Ignored malformed dependency list at {source}.", max_warnings
        )
        return []
    dependencies: list[Dependency] = []
    for item in value:
        if len(dependencies) >= max_items:
            _append_bounded(
                warnings,
                f"Dependency-count limit reached while parsing {source}.",
                max_warnings,
            )
            break
        if not isinstance(item, str):
            _append_bounded(
                warnings, f"Ignored non-string dependency at {source}.", max_warnings
            )
            continue
        dependency = _parse_requirement(item, source)
        if dependency is None:
            _append_bounded(
                warnings,
                f"Could not parse dependency at {source}.",
                max_warnings,
            )
        else:
            dependencies.append(dependency)
    return dependencies


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _poetry_table_specifier(value: dict[str, Any]) -> str:
    ordered = []
    for key in ("version", "url", "git", "path", "branch", "tag", "rev", "markers"):
        item = value.get(key)
        if isinstance(item, (str, int, float, bool)):
            if key == "version":
                rendered = _redacted_requirement_specifier(str(item))
            elif key in {"url", "git"}:
                rendered = _redacted_dependency_reference(str(item))
            elif key == "path":
                rendered = "<local-path>"
            else:
                rendered = "<redacted>"
            ordered.append(f"{key}={rendered}")
    return ", ".join(ordered) or "<table>"


def _append_bounded(items: list[str], value: str, limit: int) -> None:
    if len(items) < max(0, limit):
        items.append(value)


def _extend_bounded(items: list[Any], values: Iterable[Any], limit: int) -> None:
    remaining = max(0, limit - len(items))
    if remaining:
        items.extend(list(values)[:remaining])


def _deduplicate(dependencies: Iterable[Dependency]) -> tuple[Dependency, ...]:
    unique: dict[tuple[str, str, str], Dependency] = {}
    for dependency in dependencies:
        key = (
            re.sub(r"[-_.]+", "-", dependency.name).lower(),
            dependency.specifier,
            dependency.source,
        )
        unique[key] = dependency
    return tuple(
        unique[key]
        for key in sorted(unique, key=lambda item: (item[0], item[1], item[2]))
    )
