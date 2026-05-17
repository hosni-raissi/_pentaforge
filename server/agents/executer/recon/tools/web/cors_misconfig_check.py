"""Low-noise CORS recon helper for web and API targets."""

from __future__ import annotations

import time
from typing import Any

import httpx

from server.core.tool import tool

_DEFAULT_ORIGINS = (
    "https://evil.example",
    "null",
)
_USER_AGENT = "PentaForgeCorsCheck/1.0"


def _normalize_header_map(headers: httpx.Headers) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in headers.items()}


def _assess_cors_response(origin: str, headers: dict[str, str]) -> tuple[bool, str]:
    acao = headers.get("access-control-allow-origin", "").strip()
    acac = headers.get("access-control-allow-credentials", "").strip().lower()
    if not acao:
        return False, "No ACAO header returned for injected Origin."
    if acao == "*":
        if acac == "true":
            return True, "Wildcard ACAO combined with credentials allowance."
        return True, "Wildcard ACAO returned."
    if acao == origin:
        if acac == "true":
            return True, "Origin reflected with credentials allowance."
        return True, "Origin reflected in ACAO."
    return False, f"ACAO returned a fixed value: {acao}"


@tool(
    name="cors_misconfig_check",
    description="Perform a low-noise CORS header check against a web or API target.",
)
def cors_misconfig_check(
    target: str,
    timeout: int = 20,
) -> dict[str, Any]:
    start = time.time()
    target_url = str(target or "").strip()
    if not target_url:
        return {
            "success": False,
            "target": "",
            "total_endpoints": 0,
            "total_vulnerable": 0,
            "results": [],
            "findings": [],
            "error": "target is required",
            "execution_time": 0.0,
        }

    results: list[dict[str, Any]] = []
    findings: list[str] = []
    errors: list[str] = []
    baseline_status: int | None = None

    try:
        with httpx.Client(
            timeout=max(5, int(timeout)),
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            baseline = client.get(target_url)
            baseline_status = baseline.status_code

            for origin in _DEFAULT_ORIGINS:
                response = client.get(
                    target_url,
                    headers={
                        "Origin": origin,
                        "User-Agent": _USER_AGENT,
                    },
                )
                header_map = _normalize_header_map(response.headers)
                vulnerable, reason = _assess_cors_response(origin, header_map)
                row = {
                    "method": "GET",
                    "origin": origin,
                    "status_code": response.status_code,
                    "acao": header_map.get("access-control-allow-origin", ""),
                    "acac": header_map.get("access-control-allow-credentials", ""),
                    "vary": header_map.get("vary", ""),
                    "vulnerable": vulnerable,
                    "reason": reason,
                }
                results.append(row)
                if vulnerable:
                    findings.append(f"{origin}: {reason}")

            preflight = client.options(
                target_url,
                headers={
                    "Origin": _DEFAULT_ORIGINS[0],
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "authorization,content-type",
                    "User-Agent": _USER_AGENT,
                },
            )
            preflight_headers = _normalize_header_map(preflight.headers)
            preflight_vulnerable, preflight_reason = _assess_cors_response(
                _DEFAULT_ORIGINS[0],
                preflight_headers,
            )
            preflight_row = {
                "method": "OPTIONS",
                "origin": _DEFAULT_ORIGINS[0],
                "status_code": preflight.status_code,
                "acao": preflight_headers.get("access-control-allow-origin", ""),
                "acac": preflight_headers.get("access-control-allow-credentials", ""),
                "acam": preflight_headers.get("access-control-allow-methods", ""),
                "acah": preflight_headers.get("access-control-allow-headers", ""),
                "vary": preflight_headers.get("vary", ""),
                "vulnerable": preflight_vulnerable,
                "reason": preflight_reason,
            }
            results.append(preflight_row)
            if preflight_vulnerable:
                findings.append(f"preflight: {preflight_reason}")
    except Exception as exc:
        errors.append(str(exc))

    unique_findings = list(dict.fromkeys(item for item in findings if str(item).strip()))
    success = bool(results) and not errors
    return {
        "success": success,
        "target": target_url,
        "baseline_status": baseline_status,
        "total_endpoints": 1 if results or baseline_status is not None else 0,
        "total_vulnerable": len(unique_findings),
        "results": results[:10],
        "findings": unique_findings[:10],
        "error": "; ".join(errors[:3]) if errors else None,
        "execution_time": round(time.time() - start, 2),
    }
