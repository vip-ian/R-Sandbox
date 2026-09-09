"""Sanitized, immutable-input snapshots for shadow execution."""

from .snapshot import (
    RepositorySnapshot,
    RepositorySnapshotter,
    SnapshotLimits,
)

__all__ = [
    "RepositorySnapshot",
    "RepositorySnapshotter",
    "SnapshotLimits",
]
