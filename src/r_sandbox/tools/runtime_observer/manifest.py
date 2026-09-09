"""Symlink-aware before/after manifests for the designated output directory."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


_DEFAULT_MAX_FILES = 10_000
_DEFAULT_MAX_DIRECTORIES = 2_048
_DEFAULT_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
_DEFAULT_MAX_DEPTH = 32


class ManifestLimitExceeded(RuntimeError):
    """A manifest traversal crossed a configured safety boundary."""

    def __init__(
        self,
        limit_name: str,
        limit: int,
        observed: int,
        path: Path,
    ) -> None:
        self.limit_name = limit_name
        self.limit = limit
        self.observed = observed
        self.path = str(path)
        super().__init__(
            f"output manifest exceeded {limit_name}={limit} "
            f"(observed at least {observed}) at {path}"
        )


@dataclass(frozen=True, slots=True)
class OutputEntry:
    """One non-directory entry observed without following symbolic links."""

    path: str
    kind: str
    size: int
    modified_ns: int
    sha256: str | None = None


@dataclass(frozen=True, slots=True)
class OutputManifest:
    """A deterministic snapshot of a designated output directory."""

    root: str
    exists: bool
    entries: tuple[OutputEntry, ...] = ()

    def as_map(self) -> dict[str, OutputEntry]:
        return {entry.path: entry for entry in self.entries}


@dataclass(frozen=True, slots=True)
class ManifestDiff:
    """Created, modified, and deleted relative paths between two snapshots."""

    created: tuple[str, ...] = ()
    modified: tuple[str, ...] = ()
    deleted: tuple[str, ...] = ()

    @property
    def changed(self) -> tuple[str, ...]:
        return self.created + self.modified + self.deleted


@dataclass(slots=True)
class _ManifestBudget:
    max_files: int
    max_directories: int
    max_total_bytes: int
    max_depth: int
    files: int = 0
    directories: int = 0
    total_bytes: int = 0

    def enter_directory(self, path: Path, depth: int) -> None:
        if depth > self.max_depth:
            raise ManifestLimitExceeded(
                "max_depth", self.max_depth, depth, path
            )
        self.directories += 1
        if self.directories > self.max_directories:
            raise ManifestLimitExceeded(
                "max_directories",
                self.max_directories,
                self.directories,
                path,
            )

    def add_entry(self, path: Path, size: int) -> None:
        self.files += 1
        if self.files > self.max_files:
            raise ManifestLimitExceeded(
                "max_files", self.max_files, self.files, path
            )
        self.total_bytes += max(0, size)
        if self.total_bytes > self.max_total_bytes:
            raise ManifestLimitExceeded(
                "max_total_bytes",
                self.max_total_bytes,
                self.total_bytes,
                path,
            )


def capture_output_manifest(
    output: Path,
    *,
    hash_files: bool = False,
    max_hash_bytes: int = 8 * 1024 * 1024,
    max_files: int = _DEFAULT_MAX_FILES,
    max_directories: int = _DEFAULT_MAX_DIRECTORIES,
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES,
    max_depth: int = _DEFAULT_MAX_DEPTH,
) -> OutputManifest:
    """Capture output metadata without following files or directory symlinks.

    Hashing is opt-in and bounded.  Metadata alone is enough for the normal
    before/after report and avoids reading untrusted output back into memory.
    """

    limits = {
        "max_hash_bytes": max_hash_bytes,
        "max_files": max_files,
        "max_directories": max_directories,
        "max_total_bytes": max_total_bytes,
        "max_depth": max_depth,
    }
    for name, value in limits.items():
        if type(value) is not int or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    root = Path(os.path.abspath(output))
    try:
        root_status = root.lstat()
    except FileNotFoundError:
        return OutputManifest(root=str(root), exists=False)
    if _is_link_or_reparse(root, root_status):
        raise ValueError("output manifest root may not be a link, junction, or reparse point")
    if not stat.S_ISDIR(root_status.st_mode):
        raise NotADirectoryError(root)

    budget = _ManifestBudget(
        max_files=max_files,
        max_directories=max_directories,
        max_total_bytes=max_total_bytes,
        max_depth=max_depth,
    )
    entries: list[OutputEntry] = []
    _scan_directory(
        root,
        root,
        entries,
        depth=0,
        budget=budget,
        hash_files=hash_files,
        max_hash_bytes=max_hash_bytes,
    )
    entries.sort(key=lambda item: item.path)
    return OutputManifest(root=str(root), exists=True, entries=tuple(entries))


def diff_output_manifests(
    before: OutputManifest,
    after: OutputManifest,
) -> ManifestDiff:
    """Compare manifests captured for the same designated output path."""

    if Path(before.root) != Path(after.root):
        raise ValueError("cannot compare manifests from different output roots")
    before_map = before.as_map()
    after_map = after.as_map()
    created = tuple(sorted(after_map.keys() - before_map.keys()))
    deleted = tuple(sorted(before_map.keys() - after_map.keys()))
    modified = tuple(
        sorted(
            path
            for path in before_map.keys() & after_map.keys()
            if before_map[path] != after_map[path]
        )
    )
    return ManifestDiff(created=created, modified=modified, deleted=deleted)


def _scan_directory(
    root: Path,
    directory: Path,
    entries: list[OutputEntry],
    *,
    depth: int,
    budget: _ManifestBudget,
    hash_files: bool,
    max_hash_bytes: int,
) -> None:
    budget.enter_directory(directory, depth)
    if not _contained(root, directory):
        raise ValueError(f"output manifest path escaped its root: {directory}")
    with os.scandir(directory) as iterator:
        for child in iterator:
            child_path = Path(child.path)
            metadata = child.stat(follow_symlinks=False)
            relative = PurePosixPath(child_path.relative_to(root)).as_posix()
            mode = metadata.st_mode
            if _is_link_or_reparse(child_path, metadata):
                raise ValueError(
                    f"output manifest refuses link, junction, or reparse entry: {relative}"
                )
            if stat.S_ISDIR(mode):
                _scan_directory(
                    root,
                    child_path,
                    entries,
                    depth=depth + 1,
                    budget=budget,
                    hash_files=hash_files,
                    max_hash_bytes=max_hash_bytes,
                )
                continue
            if not stat.S_ISREG(mode):
                raise ValueError(
                    f"output manifest refuses non-regular artifact entry: {relative}"
                )

            budget.add_entry(child_path, metadata.st_size)
            kind = "file"
            digest = (
                _bounded_sha256(child_path, metadata, max_hash_bytes)
                if hash_files and metadata.st_size <= max_hash_bytes
                else None
            )
            entries.append(
                OutputEntry(
                    path=relative,
                    kind=kind,
                    size=metadata.st_size,
                    modified_ns=metadata.st_mtime_ns,
                    sha256=digest,
                )
            )


def _contained(root: Path, path: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
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


def _bounded_sha256(path: Path, expected: os.stat_result, limit: int) -> str | None:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    digest = hashlib.sha256()
    total = 0
    try:
        actual = os.fstat(descriptor)
        if not stat.S_ISREG(actual.st_mode):
            return None
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            return None
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - total))
            if not chunk:
                return digest.hexdigest()
            total += len(chunk)
            if total > limit:
                return None
            digest.update(chunk)
    finally:
        os.close(descriptor)
