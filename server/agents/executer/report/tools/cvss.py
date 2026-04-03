"""CVSS calculation and scoring tools for Report agent."""

from __future__ import annotations

import json
import math
from typing import Any

import structlog

from server.core.tool import tool
from ..config import CVSS_VERSION, CVSS_SEVERITY_THRESHOLDS

log = structlog.get_logger(__name__)

# CVSS 3.1 metric values
CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},  # Attack Vector
    "AC": {"L": 0.77, "H": 0.44},  # Attack Complexity
    "PR": {  # Privileges Required
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},  # Scope Unchanged
        "C": {"N": 0.85, "L": 0.68, "H": 0.5},   # Scope Changed
    },
    "UI": {"N": 0.85, "R": 0.62},  # User Interaction
    "C": {"N": 0, "L": 0.22, "H": 0.56},  # Confidentiality
    "I": {"N": 0, "L": 0.22, "H": 0.56},  # Integrity
    "A": {"N": 0, "L": 0.22, "H": 0.56},  # Availability
}


def _calculate_base_score(metrics: dict[str, str]) -> float:
    """Calculate CVSS 3.1 base score from metrics."""
    # Get metric values
    av = CVSS_METRICS["AV"].get(metrics.get("AV", "N"), 0.85)
    ac = CVSS_METRICS["AC"].get(metrics.get("AC", "L"), 0.77)

    scope = metrics.get("S", "U")
    pr_scope = "C" if scope == "C" else "U"
    pr = CVSS_METRICS["PR"][pr_scope].get(metrics.get("PR", "N"), 0.85)

    ui = CVSS_METRICS["UI"].get(metrics.get("UI", "N"), 0.85)
    c = CVSS_METRICS["C"].get(metrics.get("C", "N"), 0)
    i = CVSS_METRICS["I"].get(metrics.get("I", "N"), 0)
    a = CVSS_METRICS["A"].get(metrics.get("A", "N"), 0)

    # Calculate ISS (Impact Sub-Score)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    # Calculate Impact
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

    # Calculate Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    # Calculate Base Score
    if impact <= 0:
        return 0.0

    if scope == "U":
        base_score = min(impact + exploitability, 10)
    else:
        base_score = min(1.08 * (impact + exploitability), 10)

    # Round up to nearest 0.1
    return math.ceil(base_score * 10) / 10


def _get_severity(score: float) -> str:
    """Get severity label from CVSS score."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score >= 0.1:
        return "low"
    return "none"


@tool(
    name="calculate_cvss",
    description=(
        "Calculate CVSS 3.1 base score from individual metrics. "
        "Returns score, vector string, and severity rating."
    ),
)
async def calculate_cvss(
    attack_vector: str = "N",
    attack_complexity: str = "L",
    privileges_required: str = "N",
    user_interaction: str = "N",
    scope: str = "U",
    confidentiality: str = "N",
    integrity: str = "N",
    availability: str = "N",
) -> str:
    """
    Calculate CVSS 3.1 score.

    Args:
        attack_vector: N (Network), A (Adjacent), L (Local), P (Physical)
        attack_complexity: L (Low), H (High)
        privileges_required: N (None), L (Low), H (High)
        user_interaction: N (None), R (Required)
        scope: U (Unchanged), C (Changed)
        confidentiality: N (None), L (Low), H (High)
        integrity: N (None), L (Low), H (High)
        availability: N (None), L (Low), H (High)
    """
    # Validate and normalize metrics
    metrics = {
        "AV": attack_vector.upper()[:1] if attack_vector else "N",
        "AC": attack_complexity.upper()[:1] if attack_complexity else "L",
        "PR": privileges_required.upper()[:1] if privileges_required else "N",
        "UI": user_interaction.upper()[:1] if user_interaction else "N",
        "S": scope.upper()[:1] if scope else "U",
        "C": confidentiality.upper()[:1] if confidentiality else "N",
        "I": integrity.upper()[:1] if integrity else "N",
        "A": availability.upper()[:1] if availability else "N",
    }

    # Calculate score
    score = _calculate_base_score(metrics)
    severity = _get_severity(score)

    # Build vector string
    vector_string = f"CVSS:{CVSS_VERSION}/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"

    return json.dumps({
        "version": CVSS_VERSION,
        "score": score,
        "severity": severity,
        "vector_string": vector_string,
        "metrics": metrics,
    })


@tool(
    name="cvss_from_vulnerability",
    description="Automatically determine CVSS metrics from vulnerability type and context.",
)
async def cvss_from_vulnerability(
    vuln_type: str,
    is_authenticated: bool = False,
    requires_interaction: bool = False,
    network_accessible: bool = True,
    affects_other_components: bool = False,
    data_exposure: str = "none",
    data_modification: str = "none",
    service_disruption: str = "none",
) -> str:
    """
    Calculate CVSS from vulnerability context.

    Args:
        vuln_type: Type of vulnerability (sqli, xss, rce, ssrf, etc.)
        is_authenticated: Does exploitation require authentication?
        requires_interaction: Does exploitation require user interaction?
        network_accessible: Is the vulnerability remotely exploitable?
        affects_other_components: Does compromise affect other components?
        data_exposure: Level of data exposure (none, partial, full)
        data_modification: Level of data modification (none, partial, full)
        service_disruption: Level of service disruption (none, partial, full)
    """
    vuln_type = vuln_type.lower()

    # Determine metrics based on vulnerability type
    metrics = {
        "AV": "N" if network_accessible else "L",
        "AC": "L",  # Default to low
        "PR": "L" if is_authenticated else "N",
        "UI": "R" if requires_interaction else "N",
        "S": "C" if affects_other_components else "U",
        "C": {"none": "N", "partial": "L", "full": "H"}.get(data_exposure, "L"),
        "I": {"none": "N", "partial": "L", "full": "H"}.get(data_modification, "L"),
        "A": {"none": "N", "partial": "L", "full": "H"}.get(service_disruption, "N"),
    }

    # Adjust based on vulnerability type
    vuln_defaults = {
        "sqli": {"C": "H", "I": "H", "A": "L"},
        "xss": {"C": "L", "I": "L", "A": "N", "UI": "R"},
        "rce": {"C": "H", "I": "H", "A": "H"},
        "cmdi": {"C": "H", "I": "H", "A": "H"},
        "ssrf": {"C": "H", "I": "L", "A": "N"},
        "idor": {"C": "H", "I": "L", "A": "N"},
        "auth_bypass": {"C": "H", "I": "H", "A": "N", "PR": "N"},
        "path_traversal": {"C": "H", "I": "N", "A": "N"},
        "ssti": {"C": "H", "I": "H", "A": "H"},
        "xxe": {"C": "H", "I": "L", "A": "L"},
        "csrf": {"C": "N", "I": "L", "A": "N", "UI": "R"},
        "misconfig": {"C": "L", "I": "L", "A": "N", "AC": "L"},
    }

    if vuln_type in vuln_defaults:
        metrics.update(vuln_defaults[vuln_type])

    # Calculate score
    score = _calculate_base_score(metrics)
    severity = _get_severity(score)

    vector_string = f"CVSS:{CVSS_VERSION}/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"

    return json.dumps({
        "vuln_type": vuln_type,
        "version": CVSS_VERSION,
        "score": score,
        "severity": severity,
        "vector_string": vector_string,
        "metrics": metrics,
        "auto_calculated": True,
    })


@tool(
    name="parse_cvss_vector",
    description="Parse a CVSS vector string and return individual metrics and score.",
)
async def parse_cvss_vector(vector_string: str) -> str:
    """
    Parse CVSS vector string.

    Args:
        vector_string: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    """
    import re

    if not vector_string:
        return json.dumps({"error": "Vector string is required"})

    # Parse vector
    metrics = {}
    pattern = r"(AV|AC|PR|UI|S|C|I|A):([NALPHUCR])"
    matches = re.findall(pattern, vector_string.upper())

    for metric, value in matches:
        metrics[metric] = value

    if len(metrics) < 8:
        return json.dumps({"error": "Invalid or incomplete vector string"})

    # Calculate score
    score = _calculate_base_score(metrics)
    severity = _get_severity(score)

    return json.dumps({
        "vector_string": vector_string,
        "score": score,
        "severity": severity,
        "metrics": metrics,
        "metrics_expanded": {
            "attack_vector": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}.get(metrics["AV"]),
            "attack_complexity": {"L": "Low", "H": "High"}.get(metrics["AC"]),
            "privileges_required": {"N": "None", "L": "Low", "H": "High"}.get(metrics["PR"]),
            "user_interaction": {"N": "None", "R": "Required"}.get(metrics["UI"]),
            "scope": {"U": "Unchanged", "C": "Changed"}.get(metrics["S"]),
            "confidentiality": {"N": "None", "L": "Low", "H": "High"}.get(metrics["C"]),
            "integrity": {"N": "None", "L": "Low", "H": "High"}.get(metrics["I"]),
            "availability": {"N": "None", "L": "Low", "H": "High"}.get(metrics["A"]),
        },
    })
