"""Build a repository profile from bounded, static evidence.

Repository understanding is an observation step.  It never executes source,
README commands, build backends, notebook cells, or dependency tooling.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..models import RepositoryProfile
from ..tools.dependency_analyzer import DependencyAnalyzer
from ..tools.source_analyzer import AnalysisLimits, SourceAnalyzer


class RepositoryUnderstanding:
    """Coordinate deterministic source and dependency analyzers."""

    def __init__(
        self,
        *,
        limits: AnalysisLimits | None = None,
        source_analyzer: SourceAnalyzer | None = None,
        dependency_analyzer: DependencyAnalyzer | None = None,
    ) -> None:
        configured_limits = limits or AnalysisLimits()
        self.source_analyzer = source_analyzer or SourceAnalyzer(configured_limits)
        self.dependency_analyzer = dependency_analyzer or DependencyAnalyzer(
            max_file_bytes=configured_limits.max_file_bytes
        )

    def analyze(
        self, root: str | os.PathLike[str], goal: str = ""
    ) -> RepositoryProfile:
        canonical_root = Path(root).resolve(strict=True)
        source = self.source_analyzer.analyze(canonical_root)
        dependencies = self.dependency_analyzer.analyze(canonical_root)
        warnings = tuple(dict.fromkeys((*source.warnings, *dependencies.warnings)))
        return RepositoryProfile(
            root=str(canonical_root),
            goal=goal,
            summary=_summarize(source.readme_text, source.files),
            files=source.files,
            entrypoints=source.entrypoints,
            dependencies=dependencies.dependencies,
            findings=source.findings,
            warnings=warnings,
        )


def _summarize(readme: str, files: tuple[str, ...]) -> str:
    suffix_counts: dict[str, int] = {}
    for name in files:
        suffix = Path(name).suffix.lower() or "[no extension]"
        suffix_counts[suffix] = suffix_counts.get(suffix, 0) + 1
    prominent = sorted(suffix_counts.items(), key=lambda item: (-item[1], item[0]))[:4]
    inventory = ", ".join(f"{suffix}: {count}" for suffix, count in prominent)
    prefix = "README documentation was observed; " if readme else ""
    return prefix + f"static inventory of {len(files)} files" + (
        f" ({inventory})." if inventory else "."
    )
