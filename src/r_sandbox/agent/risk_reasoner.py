"""Translate repository evidence into explainable capability requests."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from r_sandbox.models import (
    CapabilityCategory,
    CapabilityRequest,
    Evidence,
    RepositoryProfile,
    RiskLevel,
)
from r_sandbox.policy.identity import capability_request_id


class RiskReasoner:
    """Deterministic baseline for the semantic permission-reasoning role.

    An LLM adapter can replace this class later, but it must emit the same
    schema and remains subject to the deterministic policy engine.
    """

    def infer(self, profile: RepositoryProfile, entrypoint=None) -> tuple[CapabilityRequest, ...]:
        entrypoint = entrypoint or (profile.entrypoints[0] if profile.entrypoints else None)
        requests: list[CapabilityRequest] = [
            self._request(
                profile,
                CapabilityCategory.FILESYSTEM,
                "read",
                "<repository>",
                "Read source, configuration, and input assets required by the research goal.",
                1.0,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.FILESYSTEM,
                "read",
                "<output>",
                "Read artifacts already present in the dedicated output directory.",
                1.0,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.FILESYSTEM,
                "write",
                "<output>",
                "Persist experiment artifacts without mutating the source repository.",
                1.0,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.FILESYSTEM,
                "read",
                "<temporary>",
                "Use bounded ephemeral scratch space that is discarded with the container.",
                1.0,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.FILESYSTEM,
                "write",
                "<temporary>",
                "Write bounded ephemeral scratch data without creating a host artifact.",
                1.0,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.FILESYSTEM,
                "read",
                "<shared-memory>",
                "Use a bounded private shared-memory filesystem for local computation.",
                1.0,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.FILESYSTEM,
                "write",
                "<shared-memory>",
                "Write only to bounded private shared memory inside the container.",
                1.0,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.RESOURCE,
                "cpu",
                "1",
                "Run the selected research entrypoint under a bounded CPU quota.",
                0.95,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.RESOURCE,
                "memory_mb",
                "1024",
                "Bound memory use for the first execution attempt.",
                0.9,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.RESOURCE,
                "pids",
                "128",
                "Bound process creation for the first execution attempt.",
                0.95,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.RESOURCE,
                "timeout_seconds",
                "300",
                "Bound wall-clock execution time for the first attempt.",
                0.95,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.RESOURCE,
                "output_mb",
                "1024",
                "Bound files written to the output mount by total logical size.",
                0.95,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.RESOURCE,
                "output_files",
                "10000",
                "Bound the number of entries created on the output mount.",
                0.95,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.RESOURCE,
                "temporary_mb",
                "64",
                "Bound the private /tmp scratch filesystem.",
                0.95,
                RiskLevel.LOW,
            ),
            self._request(
                profile,
                CapabilityCategory.RESOURCE,
                "shared_memory_mb",
                "16",
                "Bound the private /dev/shm filesystem.",
                0.95,
                RiskLevel.LOW,
            ),
        ]
        if entrypoint is not None:
            executable = Path(entrypoint.argv[0]).name
            requests.append(
                self._request(
                    profile,
                    CapabilityCategory.PROCESS,
                    "execute",
                    executable,
                    "Execute the statically selected repository entrypoint.",
                    entrypoint.confidence,
                    RiskLevel.LOW,
                    (Evidence(entrypoint.path, entrypoint.evidence),),
                )
            )

        for finding in profile.findings:
            target = self._normalize_target(finding.category, finding.target)
            requests.append(
                self._request(
                    profile,
                    finding.category,
                    finding.action,
                    target,
                    self._explain(profile, finding.reason, finding.category),
                    self._confidence(profile, finding.category, finding.action, target),
                    finding.risk,
                    finding.evidence,
                )
            )
        return self._deduplicate(requests)

    @staticmethod
    def _normalize_target(category: CapabilityCategory, target: str) -> str:
        if category == CapabilityCategory.NETWORK:
            try:
                parsed = urlparse(target)
            except ValueError:
                return "<invalid-network-target>"
            return parsed.hostname or target
        return target or "<unknown>"

    @staticmethod
    def _confidence(
        profile: RepositoryProfile,
        category: CapabilityCategory,
        action: str,
        target: str,
    ) -> float:
        goal = profile.goal.lower()
        summary = profile.summary.lower()
        normalized = target.lower()
        if category == CapabilityCategory.NETWORK:
            if action in {"send", "post", "put", "upload"}:
                return 0.05
            research_download = {
                "data", "dataset", "download", "model", "weight", "pretrained",
                "package", "install", "reproduce", "재현", "데이터", "모델",
            }
            if any(term in goal or term in normalized for term in research_download):
                return 0.9
            if any(term in summary for term in research_download):
                return 0.65
            return 0.3
        if category == CapabilityCategory.DEVICE:
            return 0.9 if any(term in goal for term in ("gpu", "cuda", "train", "학습", "inference", "추론")) else 0.4
        if category in {CapabilityCategory.SECRET, CapabilityCategory.SIDE_EFFECT}:
            return 0.1
        terms = {term for term in goal.split() if len(term) > 3}
        return 0.8 if any(term in normalized for term in terms) else 0.55

    @staticmethod
    def _explain(profile: RepositoryProfile, reason: str, category: CapabilityCategory) -> str:
        return f"Observed {category.value} behavior while pursuing '{profile.goal}': {reason}"

    @classmethod
    def _request(
        cls,
        profile: RepositoryProfile,
        category: CapabilityCategory,
        action: str,
        target: str,
        justification: str,
        confidence: float,
        risk: RiskLevel,
        evidence: tuple[Evidence, ...] = (),
    ) -> CapabilityRequest:
        normalized_confidence = max(0.0, min(1.0, confidence))
        request_id = capability_request_id(
            profile.root,
            profile.goal,
            category,
            action,
            target,
            risk,
            normalized_confidence,
            profile.snapshot_digest,
            justification,
            evidence,
            profile.authorization_context,
        )
        return CapabilityRequest(
            request_id=request_id,
            category=category,
            action=action,
            target=target,
            justification=justification,
            confidence=normalized_confidence,
            risk=risk,
            evidence=evidence,
        )

    @staticmethod
    def _deduplicate(requests: list[CapabilityRequest]) -> tuple[CapabilityRequest, ...]:
        by_id: dict[str, CapabilityRequest] = {}
        for request in requests:
            previous = by_id.get(request.request_id)
            if previous is None or list(RiskLevel).index(request.risk) > list(RiskLevel).index(previous.risk):
                by_id[request.request_id] = request
        return tuple(by_id[key] for key in sorted(by_id))
