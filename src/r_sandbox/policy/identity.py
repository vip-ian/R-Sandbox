"""Canonical, context-bound identifiers for capability approvals."""

from __future__ import annotations

from hashlib import sha256
import json
import math
from pathlib import Path
from typing import Iterable

from r_sandbox.models import CapabilityCategory, Evidence, RiskLevel


POLICY_PROFILE_VERSION = "r-sandbox-policy-v1"
RUNTIME_BACKEND_ID = "docker-local-linux-amd64-v1"


def capability_authorization_context(image: str) -> str:
    _require_utf8_text(
        image,
        "container image",
        maximum=255,
        allow_empty=False,
        enforce_bounds=True,
    )
    if "\x00" in image:
        raise ValueError("container image must be bounded text")
    return json.dumps(
        {
            "backend": RUNTIME_BACKEND_ID,
            "image": image,
            "policy": POLICY_PROFILE_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def capability_request_id(
    repository: Path | str,
    goal: str,
    category: CapabilityCategory,
    action: str,
    target: str,
    risk: RiskLevel,
    confidence: float,
    repository_digest: str = "",
    justification: str = "",
    evidence: Iterable[Evidence] = (),
    authorization_context: str = "",
) -> str:
    root = str(Path(repository).resolve(strict=False))
    _require_utf8_text(goal, "capability goal", maximum=16_384, allow_empty=False)
    _require_utf8_text(action, "capability action", maximum=128, allow_empty=False)
    _require_utf8_text(target, "capability target", maximum=8_192, allow_empty=False)
    _require_utf8_text(
        repository_digest,
        "repository digest",
        maximum=32_768,
        allow_empty=True,
    )
    _require_utf8_text(
        justification,
        "capability justification",
        maximum=16_384,
        allow_empty=True,
    )
    _require_utf8_text(
        authorization_context,
        "authorization context",
        maximum=32_768,
        allow_empty=True,
    )
    if type(category) is not CapabilityCategory or type(risk) is not RiskLevel:
        raise ValueError("capability category and risk must use the declared enum types")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ValueError("capability confidence must be a finite real number")
    try:
        numeric_confidence = float(confidence)
    except (OverflowError, TypeError, ValueError) as error:
        raise ValueError("capability confidence must be a finite real number") from error
    if not math.isfinite(numeric_confidence):
        raise ValueError("capability confidence must be a finite real number")
    try:
        evidence_items = tuple(evidence)
    except TypeError as error:
        raise ValueError("capability evidence must be an iterable of Evidence values") from error
    if len(evidence_items) > 128:
        raise ValueError("capability evidence exceeds 128 items")
    for index, item in enumerate(evidence_items):
        if type(item) is not Evidence:
            raise ValueError("capability evidence must contain exact Evidence values")
        _require_utf8_text(
            item.source,
            f"capability evidence[{index}] source",
            maximum=4_096,
            allow_empty=False,
        )
        _require_utf8_text(
            item.detail,
            f"capability evidence[{index}] detail",
            maximum=16_384,
            allow_empty=False,
        )
        if item.line is not None and (
            type(item.line) is not int or not 1 <= item.line <= 2_147_483_647
        ):
            raise ValueError("capability evidence line must be a positive bounded integer or null")
    payload = {
        "repository": root,
        "repository_digest": repository_digest,
        "goal": goal.strip(),
        "category": category.value,
        "action": action,
        "target": target,
        "risk": risk.value,
        "confidence_hex": numeric_confidence.hex(),
        "justification": justification,
        "evidence": [
            {"source": item.source, "detail": item.detail, "line": item.line}
            for item in evidence_items
        ],
        "authorization_context": authorization_context,
    }
    material = json.dumps(
        payload,
        # POSIX exposes undecodable filename bytes through surrogateescape.
        # The resolved repository path is operating-system identity, not a
        # natural-language scalar, so preserve it deterministically as JSON
        # escapes instead of rejecting an otherwise usable repository.
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii", errors="strict")
    return "cap-" + sha256(material).hexdigest()[:32]


def _require_utf8_text(
    value: object,
    field: str,
    *,
    maximum: int,
    allow_empty: bool,
    enforce_bounds: bool = False,
) -> str:
    """Reject lone surrogates at human/API text boundaries with a stable error."""

    if type(value) is not str:
        raise ValueError(f"{field} must be an exact string")
    if enforce_bounds and ((not allow_empty and not value) or len(value) > maximum):
        raise ValueError(f"{field} must be bounded text")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field} must be valid UTF-8 text without lone surrogates") from error
    return value
