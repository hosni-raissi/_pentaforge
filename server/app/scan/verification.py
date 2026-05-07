from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class VerificationTier(str, Enum):
    SIGNAL_ONLY = "signal_only"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"
    REPRODUCED = "reproduced"
    CONFIRMED = "confirmed"


@dataclass
class VerificationProof:
    tier: VerificationTier
    evidence_type: str
    description: str
    raw_proof: Any
    confidence_score: float


@dataclass
class VerificationResult:
    is_vulnerable: bool
    tier: VerificationTier
    proofs: list[VerificationProof]
    summary: str
    playbook_used: str | None = None
    reasoning: str = ""


VERIFICATION_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "xss": {
        "deterministic_markers": ["alert(1)", "print()", "string.fromcharcode"],
        "required_evidence": "Execution context confirmation (for example script execution in the DOM).",
        "min_tier_for_confirmation": VerificationTier.CONFIRMED,
    },
    "sqli": {
        "deterministic_markers": ["database_version", "current_user", "sleep_confirmed"],
        "required_evidence": "Successful data extraction or highly deterministic time-delay consistency.",
        "min_tier_for_confirmation": VerificationTier.CONFIRMED,
    },
    "ssrf": {
        "deterministic_markers": ["dns_callback", "http_callback", "metadata_received"],
        "required_evidence": "Verified out-of-band interaction or internal service response leak.",
        "min_tier_for_confirmation": VerificationTier.REPRODUCED,
    },
    "rce": {
        "deterministic_markers": ["uid=", "gid=", "linux", "windows ip configuration"],
        "required_evidence": "Deterministic command output from a known safe command.",
        "min_tier_for_confirmation": VerificationTier.CONFIRMED,
    },
    "auth_bypass": {
        "deterministic_markers": ["admin_panel_accessed", "private_data_leaked"],
        "required_evidence": "Access to a protected resource without valid credentials.",
        "min_tier_for_confirmation": VerificationTier.REPRODUCED,
    },
}


def classify_evidence(vuln_type: str, evidence_data: dict[str, Any]) -> VerificationTier:
    """Classify evidence into a verification tier based on deterministic markers."""
    vuln_key = str(vuln_type or "").lower().replace("-", "_").replace(" ", "_")
    playbook = VERIFICATION_PLAYBOOKS.get(vuln_key)

    summary = str(evidence_data.get("summary", "")).lower()
    output = str(evidence_data.get("raw_output", "")).lower()
    deterministic_validation = bool(evidence_data.get("deterministic_validation", False))

    if not playbook:
        return VerificationTier.CONFIRMED if deterministic_validation else VerificationTier.SIGNAL_ONLY

    markers = [str(marker).lower() for marker in playbook.get("deterministic_markers", [])]
    has_marker = any(marker in summary or marker in output for marker in markers)

    if deterministic_validation and has_marker:
        return VerificationTier.CONFIRMED
    if has_marker:
        return VerificationTier.REPRODUCED
    if "reproduced" in summary or "confirmed" in summary:
        return VerificationTier.REPRODUCED
    if "suspicious" in summary or "potential" in summary or "indicator" in summary:
        return VerificationTier.SIGNAL_ONLY
    return VerificationTier.NEEDS_MANUAL_REVIEW
