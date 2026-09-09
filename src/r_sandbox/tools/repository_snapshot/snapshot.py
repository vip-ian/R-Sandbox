"""Create a bounded repository snapshot without following untrusted links.

The source checkout is never mounted into a shadow container.  Instead, the
agent statically analyzes and executes the same copied tree.  Credential-like
paths, version-control metadata, links, special files, and entries beyond the
configured limits are excluded.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
from typing import Iterator


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
_METADATA_OR_CACHE_IGNORES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
    }
)
_SENSITIVE_DIRECTORY_SEQUENCES = (
    (".ssh",),
    (".aws",),
    (".azure",),
    (".config", "gcloud"),
    (".gnupg",),
    (".kube",),
)
_SENSITIVE_FILENAMES = frozenset(
    {
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "client_secret.json",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "secrets.json",
        "service-account.json",
        "service_account.json",
        "token.json",
    }
)


@dataclass(frozen=True, slots=True)
class SnapshotLimits:
    max_files: int = 5_000
    max_directories: int = 1_000
    max_depth: int = 32
    max_total_bytes: int = 256 * 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    max_warnings: int = 200

    def __post_init__(self) -> None:
        maxima = {
            "max_files": 100_000,
            "max_directories": 50_000,
            "max_depth": 256,
            "max_total_bytes": 16 * 1024 * 1024 * 1024,
            "max_file_bytes": 4 * 1024 * 1024 * 1024,
            "max_warnings": 100_000,
        }
        for field_name, maximum in maxima.items():
            value = getattr(self, field_name)
            if type(value) is not int or not 0 < value <= maximum:
                raise TypeError(
                    f"{field_name} must be an exact positive integer no greater than {maximum}"
                )


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    source: Path
    root: Path
    digest: str
    files: int
    directories: int
    total_bytes: int
    omitted_paths: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    complete: bool = True


class RepositorySnapshotter:
    """Copy one repository into a private, bounded temporary directory."""

    def __init__(self, limits: SnapshotLimits | None = None) -> None:
        self.limits = limits or SnapshotLimits()

    @contextmanager
    def create(self, source: Path) -> Iterator[RepositorySnapshot]:
        canonical = Path(source).resolve(strict=True)
        if not canonical.is_dir():
            raise ValueError("Repository input must be a directory.")
        try:
            source_device = canonical.lstat().st_dev
        except OSError as error:
            raise ValueError("Repository root metadata is unavailable.") from error
        mount_points = _linux_mount_points()
        nested_mounts = _nested_mount_points(canonical, mount_points)
        with tempfile.TemporaryDirectory(prefix="r-sandbox-snapshot-") as temporary:
            root = Path(temporary) / "repository"
            root.mkdir(mode=0o700)
            snapshot = self._copy(
                canonical,
                root,
                source_device=source_device,
                nested_mounts=nested_mounts,
            )
            if _nested_mount_points(canonical, _linux_mount_points()) != nested_mounts:
                raise ValueError(
                    "Repository mount topology changed while the snapshot was created."
                )
            if os.name == "posix":
                _set_snapshot_modes(root, sealed=True)
            try:
                yield snapshot
            finally:
                if os.name == "posix":
                    _set_snapshot_modes(root, sealed=False)

    def _copy(
        self,
        source: Path,
        destination: Path,
        *,
        source_device: int,
        nested_mounts: frozenset[Path],
    ) -> RepositorySnapshot:
        digest = sha256()
        files = 0
        directories = 1
        total_bytes = 0
        omitted: list[str] = []
        warnings: list[str] = []
        complete = True
        entries_seen = 0
        max_entries = self.limits.max_files + self.limits.max_directories
        stack: list[tuple[Path, Path, int]] = [(source, destination, 0)]

        def warn(message: str) -> None:
            if len(warnings) < self.limits.max_warnings:
                warnings.append(message)
            elif len(warnings) == self.limits.max_warnings:
                warnings.append("Additional snapshot warnings were suppressed.")

        def omit(relative: str, reason: str, *, incomplete: bool) -> None:
            nonlocal complete
            displayed_relative = _report_safe_path(relative)
            displayed_reason = _report_safe_text(reason)
            if len(omitted) < self.limits.max_warnings:
                omitted.append(displayed_relative)
            _update_digest_record(
                digest,
                b"O",
                os.fsencode(relative),
                reason.encode("utf-8", errors="surrogatepass"),
            )
            warn(f"Snapshot omitted {displayed_relative}: {displayed_reason}.")
            complete = complete and not incomplete

        stop = False
        while stack and not stop:
            source_directory, destination_directory, depth = stack.pop()
            try:
                directory_metadata = source_directory.lstat()
            except OSError as error:
                omit(
                    _relative(source, source_directory) or ".",
                    f"directory metadata unavailable ({error})",
                    incomplete=True,
                )
                continue
            if source_directory != source and _is_link_or_reparse(
                source_directory, directory_metadata
            ):
                omit(
                    _relative(source, source_directory),
                    "link, junction, or reparse-point directory rejected",
                    incomplete=True,
                )
                continue
            boundary_error = _mount_boundary_error(
                source,
                source_directory,
                directory_metadata,
                source_device,
                nested_mounts,
            )
            if source_directory != source and boundary_error is not None:
                omit(
                    _relative(source, source_directory),
                    boundary_error,
                    incomplete=True,
                )
                continue
            if not _contained(source, source_directory):
                omit(
                    _relative(source, source_directory) or ".",
                    "directory resolved outside repository root",
                    incomplete=True,
                )
                continue
            try:
                iterator = os.scandir(source_directory)
            except OSError as error:
                relative = _relative(source, source_directory)
                omit(relative or ".", f"directory could not be inspected ({error})", incomplete=True)
                continue

            entries = []
            try:
                with iterator:
                    remaining = (
                        self.limits.max_files
                        + self.limits.max_directories
                        - files
                        - directories
                    )
                    for entry in iterator:
                        if remaining <= 0 or entries_seen >= max_entries:
                            omit(
                                _relative(source, source_directory) or ".",
                                "entry-count limit reached",
                                incomplete=True,
                            )
                            stop = True
                            break
                        entries.append(entry)
                        remaining -= 1
                        entries_seen += 1
            except OSError as error:
                omit(
                    _relative(source, source_directory) or ".",
                    f"directory enumeration failed ({error})",
                    incomplete=True,
                )
                continue

            child_directories: list[tuple[Path, Path, int]] = []
            for entry in sorted(entries, key=lambda item: item.name):
                source_path = Path(entry.path)
                relative = _relative(source, source_path)
                if not _portable_report_path(relative):
                    omit(
                        relative,
                        "path is not valid, control-free UTF-8 and was withheld",
                        incomplete=True,
                    )
                    continue
                pure = PurePosixPath(relative)
                lower_parts = tuple(part.lower() for part in pure.parts)
                name_lower = entry.name.lower()

                if (
                    name_lower in _METADATA_OR_CACHE_IGNORES
                    or _ignored_directory(lower_parts, name_lower, entry)
                ):
                    if name_lower in _METADATA_OR_CACHE_IGNORES:
                        reason = (
                            "version-control, cache, or interpreter-generated tree excluded"
                        )
                    else:
                        reason = (
                            "executable dependency, environment, or build tree excluded"
                        )
                    # No ignored tree is semantically inert. Repository code may
                    # inspect VCS metadata, invoke cached bytecode, or read tool
                    # caches. Bind every exclusion into the snapshot identity and
                    # surface the resulting coverage gap to the assessor.
                    omit(relative, reason, incomplete=True)
                    continue
                if _sensitive_path(lower_parts, name_lower):
                    omit(relative, "credential-like path withheld", incomplete=False)
                    continue
                try:
                    # DirEntry stat identity fields are zeroed on some Windows
                    # Python/filesystem combinations.  Path.lstat supplies the
                    # authoritative link count and file identity used below.
                    metadata = source_path.lstat()
                except OSError as error:
                    omit(relative, f"metadata unavailable ({error})", incomplete=True)
                    continue
                mode = metadata.st_mode
                if _is_link_or_reparse(source_path, metadata):
                    omit(
                        relative,
                        "links, junctions, and reparse points are never copied",
                        incomplete=True,
                    )
                    continue
                boundary_error = _mount_boundary_error(
                    source,
                    source_path,
                    metadata,
                    source_device,
                    nested_mounts,
                )
                if boundary_error is not None:
                    omit(relative, boundary_error, incomplete=True)
                    continue
                if stat.S_ISDIR(mode):
                    if depth + 1 > self.limits.max_depth:
                        omit(relative, "directory-depth limit reached", incomplete=True)
                        continue
                    if directories >= self.limits.max_directories:
                        omit(relative, "directory-count limit reached", incomplete=True)
                        continue
                    target = destination_directory / entry.name
                    try:
                        target.mkdir(mode=0o700)
                    except OSError as error:
                        omit(relative, f"snapshot directory could not be created ({error})", incomplete=True)
                        continue
                    directories += 1
                    _update_digest_record(digest, b"D", os.fsencode(relative))
                    child_directories.append((source_path, target, depth + 1))
                    continue
                if not stat.S_ISREG(mode):
                    omit(relative, "non-regular files are never copied", incomplete=True)
                    continue
                if metadata.st_nlink != 1:
                    omit(
                        relative,
                        "multiply linked files are never copied",
                        incomplete=True,
                    )
                    continue
                if files >= self.limits.max_files:
                    omit(relative, "file-count limit reached", incomplete=True)
                    stop = True
                    break
                if metadata.st_size > self.limits.max_file_bytes:
                    omit(relative, "per-file byte limit reached", incomplete=True)
                    continue
                if total_bytes + metadata.st_size > self.limits.max_total_bytes:
                    omit(relative, "total snapshot byte limit reached", incomplete=True)
                    stop = True
                    break

                target = destination_directory / entry.name
                copied_digest, copied_size, error = _copy_regular_file(
                    source,
                    source_path,
                    target,
                    metadata,
                    source_device=source_device,
                    max_bytes=min(
                        self.limits.max_file_bytes,
                        self.limits.max_total_bytes - total_bytes,
                    ),
                )
                if error is not None:
                    omit(relative, error, incomplete=True)
                    continue
                files += 1
                total_bytes += copied_size
                _update_digest_record(
                    digest,
                    b"F",
                    os.fsencode(relative),
                    str(copied_size).encode("ascii"),
                    copied_digest.encode("ascii"),
                )

            stack.extend(reversed(child_directories))

        return RepositorySnapshot(
            source=source,
            root=destination,
            digest=digest.hexdigest(),
            files=files,
            directories=directories,
            total_bytes=total_bytes,
            omitted_paths=tuple(omitted),
            warnings=tuple(warnings),
            complete=complete,
        )


def _copy_regular_file(
    source_root: Path,
    source: Path,
    destination: Path,
    expected: os.stat_result,
    *,
    source_device: int,
    max_bytes: int,
) -> tuple[str, int, str | None]:
    read_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    digest = sha256()
    total = 0
    completed = False
    try:
        if not _contained(source_root, source):
            return "", 0, "file resolved outside repository root"
        source_descriptor = os.open(source, read_flags)
        actual = os.fstat(source_descriptor)
        current = os.stat(source, follow_symlinks=False)
        if not stat.S_ISREG(actual.st_mode) or not stat.S_ISREG(current.st_mode):
            return "", 0, "path changed type while being copied"
        if any(
            metadata.st_dev != source_device
            for metadata in (expected, actual, current)
        ):
            return "", 0, "filesystem mount boundary rejected while being copied"
        if expected.st_nlink != 1 or actual.st_nlink != 1 or current.st_nlink != 1:
            return "", 0, "multiply linked file rejected while being copied"
        if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
            return "", 0, "file identity changed before it was copied"
        if (actual.st_dev, actual.st_ino) != (current.st_dev, current.st_ino):
            return "", 0, "path changed while being copied"
        if expected.st_size != actual.st_size:
            return "", 0, "file size changed while being copied"
        destination_descriptor = os.open(destination, write_flags, 0o600)
        while True:
            chunk = os.read(source_descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                return "", 0, "file grew beyond its snapshot byte limit"
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                view = view[written:]
        final = os.fstat(source_descriptor)
        if final.st_dev != source_device:
            return "", 0, "filesystem mount boundary changed while being copied"
        if (
            (final.st_dev, final.st_ino, final.st_nlink)
            != (actual.st_dev, actual.st_ino, actual.st_nlink)
            or (final.st_size, final.st_mtime_ns)
            != (actual.st_size, actual.st_mtime_ns)
        ):
            return "", 0, "file changed while being copied"
        if not _contained(source_root, source):
            return "", 0, "file escaped repository root while being copied"
        completed = True
        return digest.hexdigest(), total, None
    except OSError as error:
        return "", 0, f"file could not be copied ({error})"
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)
        if destination.exists() and not completed:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _update_digest_record(digest, tag: bytes, *fields: bytes) -> None:
    """Hash unambiguous length-framed bytes, preserving POSIX filename identity."""

    digest.update(tag)
    digest.update(len(fields).to_bytes(2, "big"))
    for field in fields:
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)


def _portable_report_path(value: str) -> bool:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return all(ord(character) >= 32 and ord(character) != 127 for character in value)


def _report_safe_path(value: str) -> str:
    if _portable_report_path(value):
        return value
    try:
        raw = os.fsencode(value)
    except (TypeError, UnicodeError):
        raw = value.encode("utf-8", errors="backslashreplace")
    return "".join(
        chr(byte)
        if 32 <= byte < 127 and byte != 92
        else f"\\x{byte:02x}"
        for byte in raw
    )


def _report_safe_text(value: str) -> str:
    return "".join(
        character
        if 32 <= ord(character) != 127 and not 0xD800 <= ord(character) <= 0xDFFF
        else f"\\u{ord(character):04x}"
        for character in value
    )


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
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


_MOUNTINFO_ESCAPE = re.compile(r"\\([0-7]{3})")
_MAX_MOUNTINFO_BYTES = 16 * 1024 * 1024
_MAX_MOUNTINFO_LINES = 100_000


def _linux_mount_points() -> frozenset[Path]:
    """Return the current namespace's mount points, failing closed on Linux."""

    if not sys.platform.startswith("linux"):
        return frozenset()
    mountinfo = Path("/proc/self/mountinfo")
    points: set[Path] = set()
    total = 0
    try:
        with mountinfo.open("r", encoding="utf-8", errors="surrogateescape") as handle:
            for index, line in enumerate(handle):
                total += len(line.encode("utf-8", errors="surrogateescape"))
                if index >= _MAX_MOUNTINFO_LINES or total > _MAX_MOUNTINFO_BYTES:
                    raise ValueError("Linux mount table exceeds the snapshot safety bound.")
                fields = line.rstrip("\n").split(" ")
                if len(fields) < 6 or "-" not in fields:
                    raise ValueError("Linux mount table has an invalid record.")
                raw_path = fields[4]
                decoded = _MOUNTINFO_ESCAPE.sub(
                    lambda match: chr(int(match.group(1), 8)),
                    raw_path,
                )
                if not decoded.startswith("/") or "\x00" in decoded:
                    raise ValueError("Linux mount table contains an invalid mount point.")
                points.add(Path(os.path.abspath(decoded)))
    except (OSError, UnicodeError) as error:
        raise ValueError(
            "Linux mount topology is unavailable; refusing repository ingestion."
        ) from error
    return frozenset(points)


def _nested_mount_points(root: Path, mount_points: frozenset[Path]) -> frozenset[Path]:
    nested: set[Path] = set()
    for mount_point in mount_points:
        try:
            mount_point.relative_to(root)
        except ValueError:
            continue
        if mount_point != root:
            nested.add(mount_point)
    return frozenset(nested)


def _mount_boundary_error(
    root: Path,
    path: Path,
    metadata: os.stat_result,
    source_device: int,
    nested_mounts: frozenset[Path],
) -> str | None:
    if metadata.st_dev != source_device:
        return "filesystem device boundary rejected"
    try:
        relative = path.relative_to(root)
    except ValueError:
        return "path crossed the repository boundary"
    candidate = root / relative
    if candidate in nested_mounts:
        return "nested filesystem mount rejected"
    try:
        if path != root and os.path.ismount(path):
            return "nested filesystem mount rejected"
    except OSError:
        return "filesystem mount status could not be verified"
    return None


def _ignored_directory(
    lower_parts: tuple[str, ...],
    name_lower: str,
    entry: os.DirEntry[str],
) -> bool:
    try:
        is_directory = entry.is_dir(follow_symlinks=False)
    except OSError:
        return False
    return is_directory and (
        name_lower in _IGNORED_DIRECTORIES
        or any(part in _IGNORED_DIRECTORIES for part in lower_parts)
    )


def _sensitive_path(lower_parts: tuple[str, ...], name_lower: str) -> bool:
    if any(
        lower_parts[index : index + len(sequence)] == sequence
        for sequence in _SENSITIVE_DIRECTORY_SEQUENCES
        for index in range(len(lower_parts) - len(sequence) + 1)
    ):
        return True
    if name_lower == ".env" or name_lower.startswith(".env."):
        return True
    if name_lower in _SENSITIVE_FILENAMES or name_lower.endswith((".key", ".p12", ".pfx")):
        return True
    return (
        name_lower.endswith(".json")
        and (
            "credential" in name_lower
            or "client_secret" in name_lower
            or "service-account" in name_lower
            or "service_account" in name_lower
        )
    )


def _set_snapshot_modes(root: Path, *, sealed: bool) -> None:
    """Make a bind-mounted snapshot readable by an unprivileged container.

    The random TemporaryDirectory parent remains mode 0700, so these modes do
    not expose the snapshot to other host users. Docker bind-mounts ``root``
    directly, where directories/files must be readable even when a root host
    deliberately runs the container as uid 65534.
    """

    directories: list[Path] = []
    if not sealed:
        try:
            root.chmod(0o700)
        except OSError:
            return
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        directories.append(directory_path)
        if not sealed:
            for name in names:
                try:
                    (directory_path / name).chmod(0o700)
                except OSError:
                    pass
        for name in files:
            try:
                (directory_path / name).chmod(0o444 if sealed else 0o600)
            except OSError:
                pass
    for directory_path in reversed(directories):
        try:
            directory_path.chmod(0o555 if sealed else 0o700)
        except OSError:
            pass
