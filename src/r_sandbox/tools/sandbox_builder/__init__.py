"""Build a least-privilege sandbox specification from an authorized step."""

from .builder import (
    DeniedCapabilityError,
    PendingApprovalError,
    SandboxBuildError,
    SandboxBuilder,
    UnauthorizedCapabilityError,
)

__all__ = [
    "DeniedCapabilityError",
    "PendingApprovalError",
    "SandboxBuildError",
    "SandboxBuilder",
    "UnauthorizedCapabilityError",
]
