"""Deterministic tools used by the R-Sandbox agent.

The modules in this package are deliberately independent from any language
model.  They validate the model-produced plan again before it can become a
host-side effect.
"""

from .execution_supervisor import (
    DockerExecutionSupervisor,
    DryRunExecutionSupervisor,
    ExecutionSupervisor,
)
from .runtime_observer import (
    ManifestDiff,
    ManifestLimitExceeded,
    OutputEntry,
    OutputManifest,
    RuntimeObserver,
    capture_output_manifest,
    diff_output_manifests,
)
from .sandbox_builder import SandboxBuildError, SandboxBuilder

__all__ = [
    "DockerExecutionSupervisor",
    "DryRunExecutionSupervisor",
    "ExecutionSupervisor",
    "ManifestDiff",
    "ManifestLimitExceeded",
    "OutputEntry",
    "OutputManifest",
    "RuntimeObserver",
    "SandboxBuildError",
    "SandboxBuilder",
    "capture_output_manifest",
    "diff_output_manifests",
]
