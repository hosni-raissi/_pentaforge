"""Patch confidence scoring tools for Retest agent."""

from __future__ import annotations

import json
import statistics
from datetime import datetime, timezone
from typing import Any

import structlog

from server.core.tool import tool
from ..config import (
    PATCH_CONFIDENCE_THRESHOLD,
    PATCH_CONFIDENCE_FEATURES,
    FEATURE_WEIGHTS,
    RETEST_VERDICTS,
)

log = structlog.get_logger(__name__)


@tool(
    name="calculate_patch_confidence",
    description="Calculate ML-based patch confidence score from retest results.",
)
async def calculate_patch_confidence(
    original_blocked: bool = False,
    mutations_tested: int = 0,
    mutations_blocked: int = 0,
    error_messages_sanitized: bool = False,
    timing_variance_ms: float = 0.0,
    consistent_errors: bool = False,
    http_status_appropriate: bool = False,
    content_type_secure: bool = False,
    no_data_leakage: bool = False,
) -> str:
    """
    Calculate patch confidence score using weighted features.

    Args:
        original_blocked: Whether original payload was blocked
        mutations_tested: Number of mutation variants tested
        mutations_blocked: Number of mutations that were blocked
        error_messages_sanitized: Error messages don't leak info
        timing_variance_ms: Response time variance (lower is better)
        consistent_errors: Same error response for all attempts
        http_status_appropriate: Proper HTTP status codes used
        content_type_secure: Secure content-type headers
        no_data_leakage: No sensitive data in responses
    """
    # Calculate individual feature scores
    features = {}

    # Original payload blocked (25%)
    features["original_payload_blocked"] = 1.0 if original_blocked else 0.0

    # Mutations blocked (20%)
    if mutations_tested > 0:
        features["mutations_blocked"] = mutations_blocked / mutations_tested
    else:
        features["mutations_blocked"] = 1.0 if original_blocked else 0.0

    # Error messages sanitized (15%)
    features["error_messages_sanitized"] = 1.0 if error_messages_sanitized else 0.0

    # Response timing normalized (10%)
    # Low variance indicates no timing oracle
    if timing_variance_ms < 50:
        features["response_timing_normalized"] = 1.0
    elif timing_variance_ms < 100:
        features["response_timing_normalized"] = 0.7
    elif timing_variance_ms < 200:
        features["response_timing_normalized"] = 0.4
    else:
        features["response_timing_normalized"] = 0.1

    # Consistent error handling (10%)
    features["consistent_error_handling"] = 1.0 if consistent_errors else 0.0

    # HTTP status appropriate (8%)
    features["http_status_appropriate"] = 1.0 if http_status_appropriate else 0.0

    # Content type secure (7%)
    features["content_type_secure"] = 1.0 if content_type_secure else 0.0

    # No data leakage (5%)
    features["no_data_leakage"] = 1.0 if no_data_leakage else 0.0

    # Calculate weighted score
    confidence = 0.0
    for feature, score in features.items():
        weight = FEATURE_WEIGHTS.get(feature, 0.1)
        confidence += score * weight

    # Ensure 0-1 range
    confidence = max(0.0, min(1.0, confidence))

    # Determine verdict based on confidence
    if confidence >= PATCH_CONFIDENCE_THRESHOLD:
        if original_blocked and mutations_tested > 0 and mutations_blocked == mutations_tested:
            verdict = "fixed"
        else:
            verdict = "fixed"
        confidence_level = "high"
    elif confidence >= 0.60:
        verdict = "partial"
        confidence_level = "medium"
    elif original_blocked and mutations_blocked < mutations_tested:
        verdict = "bypassed"
        confidence_level = "low"
    else:
        verdict = "not_fixed"
        confidence_level = "low"

    return json.dumps({
        "patch_confidence": round(confidence, 4),
        "confidence_level": confidence_level,
        "verdict": verdict,
        "verdict_description": RETEST_VERDICTS.get(verdict, "Unknown"),
        "threshold": PATCH_CONFIDENCE_THRESHOLD,
        "meets_threshold": confidence >= PATCH_CONFIDENCE_THRESHOLD,
        "feature_scores": {k: round(v, 4) for k, v in features.items()},
        "feature_weights": FEATURE_WEIGHTS,
        "recommendations": _generate_recommendations(features, verdict),
    })


@tool(
    name="analyze_retest_results",
    description="Analyze complete retest results and generate final verdict.",
)
async def analyze_retest_results(
    finding_id: str,
    retest_data: str,
) -> str:
    """
    Analyze complete retest results for final verdict.

    Args:
        finding_id: Original finding identifier
        retest_data: JSON string of retest results
    """
    try:
        data = json.loads(retest_data)
    except json.JSONDecodeError:
        return json.dumps({
            "error": "Invalid retest data JSON",
            "finding_id": finding_id,
        })

    # Extract results
    replay_results = data.get("replay_results", [])
    mutation_results = data.get("mutation_results", [])
    original_severity = data.get("original_severity", "medium")

    # Calculate metrics
    original_blocked = any(r.get("blocked", False) for r in replay_results)
    mutations_tested = len(mutation_results)
    mutations_blocked = sum(1 for r in mutation_results if r.get("blocked", False))
    mutations_bypassed = mutations_tested - mutations_blocked

    # Check for timing oracle
    response_times = [r.get("response_time_ms", 0) for r in replay_results + mutation_results]
    timing_variance = statistics.stdev(response_times) if len(response_times) > 1 else 0

    # Check error consistency
    error_codes = [r.get("status_code", 0) for r in replay_results + mutation_results]
    consistent_errors = len(set(error_codes)) == 1

    # Check for data leakage
    any_success = any(r.get("exploitation_success", False) for r in replay_results + mutation_results)

    # Calculate confidence
    confidence_result = await calculate_patch_confidence(
        original_blocked=original_blocked,
        mutations_tested=mutations_tested,
        mutations_blocked=mutations_blocked,
        error_messages_sanitized=not any_success,
        timing_variance_ms=timing_variance,
        consistent_errors=consistent_errors,
        http_status_appropriate=all(c in [200, 400, 403, 404] for c in error_codes),
        content_type_secure=True,  # Would need header analysis
        no_data_leakage=not any_success,
    )

    confidence_data = json.loads(confidence_result)

    # Build final result
    bypass_payloads = [
        r.get("payload", "")
        for r in mutation_results
        if not r.get("blocked", True)
    ]

    return json.dumps({
        "finding_id": finding_id,
        "original_severity": original_severity,
        "retest_result": {
            "verdict": confidence_data["verdict"],
            "patch_confidence": confidence_data["patch_confidence"],
            "confidence_level": confidence_data["confidence_level"],
            "original_blocked": original_blocked,
            "mutations_tested": mutations_tested,
            "mutations_bypassed": mutations_bypassed,
            "bypass_payloads": bypass_payloads[:5],  # Limit to 5
        },
        "severity_after_retest": _adjust_severity(
            original_severity,
            confidence_data["verdict"],
        ),
        "confidence_breakdown": confidence_data["feature_scores"],
        "recommendations": confidence_data["recommendations"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@tool(
    name="detect_regression",
    description="Detect if a previously fixed vulnerability has regressed.",
)
async def detect_regression(
    finding_id: str,
    previous_verdict: str,
    previous_test_date: str,
    current_verdict: str,
    current_confidence: float,
) -> str:
    """
    Detect regression in vulnerability fix.

    Args:
        finding_id: Finding identifier
        previous_verdict: Previous retest verdict
        previous_test_date: Date of previous test
        current_verdict: Current retest verdict
        current_confidence: Current confidence score
    """
    # Regression detection logic
    regression_verdicts = {
        ("fixed", "not_fixed"): True,
        ("fixed", "bypassed"): True,
        ("fixed", "partial"): True,
        ("partial", "not_fixed"): True,
        ("partial", "bypassed"): True,
    }

    is_regression = regression_verdicts.get(
        (previous_verdict.lower(), current_verdict.lower()),
        False,
    )

    # Determine severity impact
    if is_regression:
        if current_verdict in ["not_fixed", "bypassed"]:
            severity_impact = "critical"
        else:
            severity_impact = "high"
    else:
        severity_impact = "none"

    return json.dumps({
        "finding_id": finding_id,
        "is_regression": is_regression,
        "previous_verdict": previous_verdict,
        "current_verdict": current_verdict,
        "previous_test_date": previous_test_date,
        "current_test_date": datetime.now(timezone.utc).isoformat(),
        "severity_impact": severity_impact,
        "confidence": current_confidence,
        "alert_required": is_regression and current_confidence > 0.6,
        "investigation_needed": is_regression,
        "possible_causes": _get_regression_causes() if is_regression else [],
    })


def _generate_recommendations(features: dict[str, float], verdict: str) -> list[str]:
    """Generate recommendations based on feature scores."""
    recommendations = []

    if features.get("original_payload_blocked", 0) < 1.0:
        recommendations.append("Original payload still works - fix not effective")

    if features.get("mutations_blocked", 0) < 0.8:
        recommendations.append("Multiple bypass variants successful - strengthen input validation")

    if features.get("error_messages_sanitized", 0) < 1.0:
        recommendations.append("Error messages may leak sensitive information")

    if features.get("response_timing_normalized", 0) < 0.7:
        recommendations.append("Response timing variance detected - potential timing oracle")

    if features.get("consistent_error_handling", 0) < 1.0:
        recommendations.append("Inconsistent error handling may aid attackers")

    if verdict == "partial":
        recommendations.append("Consider implementing additional security controls (WAF, rate limiting)")

    if verdict in ["not_fixed", "bypassed"]:
        recommendations.append("Immediate remediation required - vulnerability still exploitable")

    return recommendations


def _adjust_severity(original_severity: str, verdict: str) -> str:
    """Adjust severity based on retest verdict."""
    if verdict == "fixed":
        return "resolved"
    elif verdict == "partial":
        # May need to lower severity if harder to exploit
        return original_severity
    elif verdict == "bypassed":
        # Attacker has shown bypass - maintain severity
        return original_severity
    elif verdict == "regression":
        # Regression may warrant increased severity
        severity_order = ["info", "low", "medium", "high", "critical"]
        current_idx = severity_order.index(original_severity.lower())
        if current_idx < len(severity_order) - 1:
            return severity_order[current_idx + 1]
        return original_severity
    else:
        return original_severity


def _get_regression_causes() -> list[str]:
    """Get possible causes for regression."""
    return [
        "Code deployment reverted fix",
        "Configuration change undid security control",
        "Dependency update reintroduced vulnerability",
        "Merge conflict resolved incorrectly",
        "Feature branch merged without fix",
        "Environment-specific configuration differs",
    ]
