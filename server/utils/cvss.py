from __future__ import annotations

import math
from typing import Any

try:
    from cvss import CVSS3 as _CVSS3
except Exception:  # pragma: no cover - fallback is covered instead
    _CVSS3 = None

_REQUIRED_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_PR_WEIGHTS_SCOPE_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_WEIGHTS_SCOPE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_IMPACT_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}
_VALID_SCOPE_VALUES = {"U", "C"}
_DEFAULT_VERSION = "CVSS:3.1"


def _round_up_1_decimal(value: float) -> float:
    return math.ceil((value - 1e-10) * 10.0) / 10.0


def _severity_from_score(score: float) -> str:
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def normalize_cvss_vector(vector_string: Any) -> str:
    raw = str(vector_string or "").strip()
    if not raw:
        raise ValueError("CVSS vector is required")

    parts = [part.strip() for part in raw.split("/") if part.strip()]
    if not parts:
        raise ValueError("Invalid CVSS vector")

    version = parts[0].upper()
    if version not in {"CVSS:3.0", "CVSS:3.1"}:
        raise ValueError("Only CVSS v3.0 and v3.1 vectors are supported")

    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError(f"Invalid CVSS metric segment: {part}")
        key, value = part.split(":", 1)
        metrics[key.strip().upper()] = value.strip().upper()

    missing = [name for name in _REQUIRED_BASE_METRICS if name not in metrics]
    if missing:
        raise ValueError(f"Missing CVSS metrics: {', '.join(missing)}")

    if metrics["AV"] not in _AV_WEIGHTS:
        raise ValueError("Invalid AV value")
    if metrics["AC"] not in _AC_WEIGHTS:
        raise ValueError("Invalid AC value")
    if metrics["UI"] not in _UI_WEIGHTS:
        raise ValueError("Invalid UI value")
    if metrics["S"] not in _VALID_SCOPE_VALUES:
        raise ValueError("Invalid S value")
    if metrics["PR"] not in _PR_WEIGHTS_SCOPE_UNCHANGED:
        raise ValueError("Invalid PR value")
    for metric_name in ("C", "I", "A"):
        if metrics[metric_name] not in _IMPACT_WEIGHTS:
            raise ValueError(f"Invalid {metric_name} value")

    ordered_parts = [version]
    ordered_parts.extend(f"{name}:{metrics[name]}" for name in _REQUIRED_BASE_METRICS)
    extras = [
        f"{key}:{value}"
        for key, value in metrics.items()
        if key not in _REQUIRED_BASE_METRICS
    ]
    ordered_parts.extend(sorted(extras))
    return "/".join(ordered_parts)


def _calculate_cvss_fallback(vector_string: str) -> dict[str, Any]:
    normalized = normalize_cvss_vector(vector_string)
    metrics = {
        segment.split(":", 1)[0]: segment.split(":", 1)[1]
        for segment in normalized.split("/")[1:]
        if ":" in segment
    }

    scope = metrics["S"]
    pr_weights = (
        _PR_WEIGHTS_SCOPE_CHANGED
        if scope == "C"
        else _PR_WEIGHTS_SCOPE_UNCHANGED
    )

    exploitability = 8.22 * (
        _AV_WEIGHTS[metrics["AV"]]
        * _AC_WEIGHTS[metrics["AC"]]
        * pr_weights[metrics["PR"]]
        * _UI_WEIGHTS[metrics["UI"]]
    )

    confidentiality = _IMPACT_WEIGHTS[metrics["C"]]
    integrity = _IMPACT_WEIGHTS[metrics["I"]]
    availability = _IMPACT_WEIGHTS[metrics["A"]]
    isc_base = 1.0 - (
        (1.0 - confidentiality)
        * (1.0 - integrity)
        * (1.0 - availability)
    )

    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _round_up_1_decimal(min(impact + exploitability, 10.0))
    else:
        score = _round_up_1_decimal(min(1.08 * (impact + exploitability), 10.0))

    return {
        "score": float(score),
        "severity": _severity_from_score(score),
        "vector": normalized,
    }


def calculate_cvss(vector_string: str) -> dict[str, Any]:
    normalized = normalize_cvss_vector(vector_string)
    if _CVSS3 is not None:
        try:
            calculated = _CVSS3(normalized)
            score = float(calculated.base_score)
            severity = str(calculated.severities()[0]).strip() or _severity_from_score(score)
            return {
                "score": score,
                "severity": severity,
                "vector": normalized,
            }
        except Exception:
            pass
    return _calculate_cvss_fallback(normalized)


def extract_cvss_vector(*sources: Any) -> str:
    candidate_keys = ("cvss_vector", "cvssVector", "vector", "vector_string")
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in candidate_keys:
            value = str(source.get(key, "")).strip()
            if value.upper().startswith("CVSS:3."):
                return value
        nested = source.get("evidence")
        if isinstance(nested, dict):
            for key in candidate_keys:
                value = str(nested.get(key, "")).strip()
                if value.upper().startswith("CVSS:3."):
                    return value
    return ""


def _collect_candidate_text(*sources: Any) -> str:
    parts: list[str] = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in (
            "title",
            "name",
            "category",
            "summary",
            "description",
            "severity",
            "vulnerability_type",
            "expected_indicator",
        ):
            value = str(source.get(key, "")).strip()
            if value:
                parts.append(value)
        evidence = source.get("evidence")
        if isinstance(evidence, dict):
            for key in (
                "verification_summary",
                "normalized_summary",
                "vulnerability_type",
                "expected_indicator",
            ):
                value = str(evidence.get(key, "")).strip()
                if value:
                    parts.append(value)
    return " ".join(parts).lower()


def infer_cvss_vector(*sources: Any) -> str:
    text = _collect_candidate_text(*sources)
    if not text:
        return ""

    if any(marker in text for marker in (
        "werkzeug",
        "debugger",
        "remote code execution",
        "arbitrary code execution",
        "command injection",
        "code injection",
        "rce",
    )):
        return f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

    if any(marker in text for marker in (
        "static session token",
        "hardcoded session",
        "session impersonation",
        "session hijack",
        "session hijacking",
        "token reuse",
        "impersonation",
    )):
        return f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

    if "session fixation" in text:
        return f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"

    if any(marker in text for marker in ("auth bypass", "authentication bypass")):
        return f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"

    if any(marker in text for marker in ("idor", "insecure direct object reference", "access control")):
        if "unauthenticated" in text:
            return f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        return f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"

    if "ssrf" in text or "server-side request forgery" in text:
        return f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"

    if "sql injection" in text or "sqli" in text:
        return f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    if any(marker in text for marker in ("xss", "cross-site scripting")):
        return f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

    severity_text = text
    if "critical" in severity_text:
        return f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    if "high" in severity_text:
        return f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    if "medium" in severity_text:
        return f"{_DEFAULT_VERSION}/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"
    if "low" in severity_text:
        return f"{_DEFAULT_VERSION}/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"
    return ""


def enrich_payload_with_cvss(
    payload: dict[str, Any],
    *sources: Any,
    set_severity: bool = True,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    vector = extract_cvss_vector(payload, *sources)
    if not vector:
        vector = infer_cvss_vector(payload, *sources)
    if not vector:
        return payload

    try:
        result = calculate_cvss(vector)
    except ValueError:
        return payload

    payload["cvss"] = result["score"]
    payload["cvss_score"] = result["score"]
    payload["cvss_vector"] = result["vector"]
    payload["cvss_severity"] = str(result["severity"]).strip().lower()
    if set_severity:
        payload["severity"] = payload["cvss_severity"]

    evidence = payload.get("evidence")
    if isinstance(evidence, dict):
        evidence.setdefault("cvss_score", payload["cvss_score"])
        evidence.setdefault("cvss_vector", payload["cvss_vector"])
        evidence.setdefault("cvss_severity", payload["cvss_severity"])

    return payload
