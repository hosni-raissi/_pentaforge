"""Payload replay tools for Retest agent."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode

import httpx
import structlog

from server.core.tool import tool
from ..config import (
    MAX_REPLAY_ATTEMPTS,
    REPLAY_DELAY_SECONDS,
    REPLAY_TIMEOUT_SECONDS,
)

log = structlog.get_logger(__name__)


@tool(
    name="replay_payload",
    description="Replay an original exploit payload against a patched endpoint to verify fix.",
)
async def replay_payload(
    url: str,
    method: str = "GET",
    payload: str = "",
    headers: str = "{}",
    body: str = "",
    cookies: str = "",
    original_response_hash: str = "",
) -> str:
    """
    Replay original payload to verify remediation.

    Args:
        url: Target URL with payload in place
        method: HTTP method
        payload: The original payload (for reference)
        headers: JSON string of headers
        body: Request body
        cookies: Cookie string
        original_response_hash: Hash of original response for comparison
    """
    try:
        headers_dict = json.loads(headers) if headers else {}
    except json.JSONDecodeError:
        headers_dict = {}

    # Add cookie header if provided
    if cookies:
        headers_dict["Cookie"] = cookies

    results = []
    blocked = False
    success = False

    async with httpx.AsyncClient(
        timeout=REPLAY_TIMEOUT_SECONDS,
        follow_redirects=True,
        verify=False,
    ) as client:
        for attempt in range(1, MAX_REPLAY_ATTEMPTS + 1):
            try:
                start_time = time.time()

                if method.upper() == "GET":
                    response = await client.get(url, headers=headers_dict)
                elif method.upper() == "POST":
                    response = await client.post(url, headers=headers_dict, content=body)
                elif method.upper() == "PUT":
                    response = await client.put(url, headers=headers_dict, content=body)
                elif method.upper() == "DELETE":
                    response = await client.delete(url, headers=headers_dict)
                else:
                    response = await client.request(
                        method.upper(), url, headers=headers_dict, content=body
                    )

                elapsed = time.time() - start_time
                response_hash = hashlib.sha256(response.content).hexdigest()[:16]

                # Analyze response for block indicators
                is_blocked = _detect_blocking(response)
                is_success = _detect_exploitation_success(response, payload)

                result = {
                    "attempt": attempt,
                    "status_code": response.status_code,
                    "response_length": len(response.content),
                    "response_time_ms": round(elapsed * 1000, 2),
                    "response_hash": response_hash,
                    "blocked": is_blocked,
                    "exploitation_success": is_success,
                    "block_indicators": _get_block_indicators(response) if is_blocked else [],
                }

                results.append(result)

                if is_blocked:
                    blocked = True
                if is_success:
                    success = True

                # Compare with original
                if original_response_hash:
                    result["matches_original"] = response_hash == original_response_hash

                # Delay between attempts
                if attempt < MAX_REPLAY_ATTEMPTS:
                    await asyncio.sleep(REPLAY_DELAY_SECONDS)

            except httpx.TimeoutException:
                results.append({
                    "attempt": attempt,
                    "error": "timeout",
                    "blocked": True,
                })
                blocked = True
            except Exception as e:
                results.append({
                    "attempt": attempt,
                    "error": str(e),
                    "blocked": False,
                })

    # Calculate overall verdict
    if success:
        verdict = "vulnerable"
    elif blocked:
        verdict = "blocked"
    else:
        verdict = "inconclusive"

    return json.dumps({
        "url": url,
        "method": method,
        "payload_tested": payload[:100] + "..." if len(payload) > 100 else payload,
        "verdict": verdict,
        "blocked": blocked,
        "exploitation_detected": success,
        "attempts": len(results),
        "results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@tool(
    name="replay_finding",
    description="Replay a complete finding from stored evidence.",
)
async def replay_finding(
    finding_id: str,
    finding_data: str,
) -> str:
    """
    Replay finding from stored data.

    Args:
        finding_id: Unique finding identifier
        finding_data: JSON string containing finding details
    """
    try:
        finding = json.loads(finding_data)
    except json.JSONDecodeError:
        return json.dumps({
            "error": "Invalid finding data JSON",
            "finding_id": finding_id,
        })

    # Extract replay parameters from finding
    url = finding.get("affected_url", finding.get("url", ""))
    method = finding.get("method", "GET")
    payload = finding.get("payload", "")
    headers = json.dumps(finding.get("headers", {}))
    body = finding.get("body", "")
    cookies = finding.get("cookies", "")
    original_hash = finding.get("response_hash", "")

    if not url:
        return json.dumps({
            "error": "No URL found in finding data",
            "finding_id": finding_id,
        })

    # Call replay_payload
    result = await replay_payload(
        url=url,
        method=method,
        payload=payload,
        headers=headers,
        body=body,
        cookies=cookies,
        original_response_hash=original_hash,
    )

    result_data = json.loads(result)
    result_data["finding_id"] = finding_id
    result_data["original_severity"] = finding.get("severity", "unknown")

    return json.dumps(result_data)


@tool(
    name="compare_responses",
    description="Compare original and retest responses for differential analysis.",
)
async def compare_responses(
    original_response: str,
    retest_response: str,
    payload: str = "",
) -> str:
    """
    Compare original exploit response with retest response.

    Args:
        original_response: Original response content/hash
        retest_response: Retest response content/hash
        payload: Payload used (for reference)
    """
    original_hash = hashlib.sha256(original_response.encode()).hexdigest()[:16]
    retest_hash = hashlib.sha256(retest_response.encode()).hexdigest()[:16]

    # Analyze differences
    len_diff = len(retest_response) - len(original_response)
    hashes_match = original_hash == retest_hash

    # Check for payload reflection
    payload_in_original = payload.lower() in original_response.lower() if payload else False
    payload_in_retest = payload.lower() in retest_response.lower() if payload else False

    # Determine verdict
    if hashes_match:
        verdict = "identical"
    elif payload_in_original and not payload_in_retest:
        verdict = "payload_blocked"
    elif not payload_in_original and payload_in_retest:
        verdict = "new_vulnerability"
    else:
        verdict = "different"

    return json.dumps({
        "original_hash": original_hash,
        "retest_hash": retest_hash,
        "hashes_match": hashes_match,
        "length_difference": len_diff,
        "payload_in_original": payload_in_original,
        "payload_in_retest": payload_in_retest,
        "verdict": verdict,
        "analysis_notes": _generate_diff_notes(
            original_response, retest_response, payload
        ),
    })


def _detect_blocking(response: httpx.Response) -> bool:
    """Detect if response indicates blocking."""
    # Status code indicators
    if response.status_code in [403, 406, 429, 503]:
        return True

    # Content indicators
    content_lower = response.text.lower()
    block_indicators = [
        "blocked",
        "forbidden",
        "access denied",
        "waf",
        "firewall",
        "security violation",
        "attack detected",
        "suspicious activity",
        "rate limit",
        "too many requests",
        "cloudflare",
        "akamai",
        "imperva",
        "f5 asm",
    ]

    for indicator in block_indicators:
        if indicator in content_lower:
            return True

    return False


def _detect_exploitation_success(response: httpx.Response, payload: str) -> bool:
    """Detect if exploitation was successful."""
    content = response.text

    # Check for payload reflection without encoding
    if payload and payload in content:
        # Check if it's not HTML-encoded
        encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
        if encoded_payload not in content:
            return True

    # Check for common exploitation indicators
    success_indicators = [
        "root:",  # /etc/passwd leak
        "uid=",   # Command execution
        "syntax error",  # SQL error
        "mysql_",  # MySQL error
        "postgresql",  # PostgreSQL error
        "sqlite",  # SQLite error
        "stack trace",  # Application error
    ]

    content_lower = content.lower()
    for indicator in success_indicators:
        if indicator in content_lower:
            return True

    return False


def _get_block_indicators(response: httpx.Response) -> list[str]:
    """Get specific block indicators found."""
    indicators = []
    content_lower = response.text.lower()

    checks = {
        "waf_block": ["waf", "firewall", "blocked by"],
        "rate_limit": ["rate limit", "too many requests", "429"],
        "forbidden": ["forbidden", "403", "access denied"],
        "cloudflare": ["cloudflare", "cf-ray"],
        "security_rule": ["security rule", "attack detected", "violation"],
    }

    for indicator_type, patterns in checks.items():
        for pattern in patterns:
            if pattern in content_lower:
                indicators.append(indicator_type)
                break

    if response.status_code == 403:
        indicators.append("http_403")
    if response.status_code == 429:
        indicators.append("http_429")

    return list(set(indicators))


def _generate_diff_notes(original: str, retest: str, payload: str) -> str:
    """Generate notes about response differences."""
    notes = []

    if len(retest) < len(original) * 0.5:
        notes.append("Retest response significantly shorter")
    elif len(retest) > len(original) * 1.5:
        notes.append("Retest response significantly longer")

    if payload:
        if payload in original and payload not in retest:
            notes.append("Payload no longer reflected - likely blocked")
        elif payload not in original and payload in retest:
            notes.append("Payload now reflected - potential new vulnerability")

    return "; ".join(notes) if notes else "Responses differ but no significant security indicators"
