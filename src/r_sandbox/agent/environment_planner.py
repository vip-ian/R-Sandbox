"""Build a non-executing, evidence-backed project environment plan."""

from __future__ import annotations

import re

from r_sandbox.models import (
    EnvironmentPlan,
    EnvironmentReadiness,
    RepositoryProfile,
)


_DIGEST_PIN = re.compile(r"@sha256:[a-fA-F0-9]{64}\Z")


class EnvironmentPlanner:
    """Describe runtime inputs without invoking a package installer.

    Dependency resolution/building is intentionally not performed on the host.
    Repositories with declared third-party packages require a separately
    reviewed, prebuilt image before environment compatibility can be claimed.
    """

    def plan(self, profile: RepositoryProfile, image: str) -> EnvironmentPlan:
        image_pinned = bool(_DIGEST_PIN.search(image))
        warnings: list[str] = []
        if not image_pinned:
            warnings.append(
                "Container image is referenced by a mutable tag rather than a sha256 digest."
            )
        if profile.dependencies:
            readiness = EnvironmentReadiness.PREBUILT_IMAGE_REQUIRED
            warnings.append(
                "Declared third-party dependencies are not installed automatically; "
                "provide a reviewed prebuilt image containing the exact dependency set."
            )
            unpinned = [
                item.name
                for item in profile.dependencies
                if not item.specifier.strip().startswith("==")
            ]
            if unpinned:
                warnings.append(
                    f"{len(unpinned)} declared dependency entry/entries are not exact == pins."
                )
        else:
            readiness = EnvironmentReadiness.NO_DECLARED_DEPENDENCIES
            warnings.append(
                "No supported dependency declaration was found; this does not prove "
                "that the project uses only the Python standard library."
            )

        return EnvironmentPlan(
            runtime="python",
            image=image,
            image_pinned=image_pinned,
            readiness=readiness,
            dependencies=profile.dependencies,
            warnings=tuple(warnings),
        )
