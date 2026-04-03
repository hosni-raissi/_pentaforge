"""Vision model validation tools for Verify agent."""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path
from typing import Any

import structlog

from server.core.tool import tool
from ..config import (
    VISION_MODEL,
    VISION_TIMEOUT,
    VISION_MAX_TOKENS,
    VISION_CONFIDENCE_THRESHOLD,
    FALSE_POSITIVE_THRESHOLD,
)
from ..prompts import VISION_ANALYSIS_PROMPT, EVIDENCE_COMPARISON_PROMPT

log = structlog.get_logger(__name__)


def _load_image_as_base64(image_path: str) -> str:
    """Load image and convert to base64."""
    with open(image_path, "rb") as f:
        return base64.b64encode(f.read()).decode()


def _parse_json_from_response(text: str) -> dict[str, Any]:
    """Extract JSON from LLM response."""
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown code block
    json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding JSON object
    brace_match = re.search(r"\{[\s\S]*\}", text)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    return {}


@tool(
    name="analyze_screenshot_with_vision",
    description=(
        "Submit screenshot to vision model for false positive detection and vulnerability validation. "
        "Returns confidence scores and bounding box suggestions for evidence highlighting."
    ),
)
async def analyze_screenshot_with_vision(
    screenshot_path: str,
    vuln_type: str,
    expected_indicator: str,
    target: str = "",
) -> str:
    """
    Analyze screenshot with vision model.

    Args:
        screenshot_path: Path to the screenshot file
        vuln_type: Type of vulnerability (xss, sqli, rce, ssrf, etc.)
        expected_indicator: What we expect to see if exploitation succeeded
        target: Target URL/endpoint for context
    """
    if not screenshot_path or not os.path.exists(screenshot_path):
        return json.dumps({"error": f"Screenshot not found: {screenshot_path}"})

    try:
        # Load image
        image_b64 = _load_image_as_base64(screenshot_path)

        # Build prompt
        prompt = VISION_ANALYSIS_PROMPT.format(
            vuln_type=vuln_type,
            expected_indicator=expected_indicator,
            target=target,
        )

        # Call vision model
        result = await _call_vision_model(prompt, image_b64)

        if "error" in result:
            return json.dumps(result)

        # Parse response
        analysis = _parse_json_from_response(result.get("response", ""))

        if not analysis:
            analysis = {
                "vulnerability_confirmed": False,
                "confidence": 0.0,
                "analysis_notes": result.get("response", "Unable to parse response"),
                "needs_manual_review": True,
            }

        # Add metadata
        analysis["screenshot_path"] = screenshot_path
        analysis["vuln_type"] = vuln_type
        analysis["model_used"] = VISION_MODEL

        # Determine verification status
        confidence = float(analysis.get("confidence", 0))
        if confidence >= VISION_CONFIDENCE_THRESHOLD:
            analysis["verification_status"] = "confirmed"
        elif confidence >= FALSE_POSITIVE_THRESHOLD:
            analysis["verification_status"] = "likely_false_positive"
        else:
            analysis["verification_status"] = "inconclusive"

        return json.dumps(analysis)

    except Exception as e:
        log.error("vision_analysis_failed", error=str(e))
        return json.dumps({"error": str(e), "screenshot_path": screenshot_path})


async def _call_vision_model(prompt: str, image_b64: str) -> dict[str, Any]:
    """Call vision model (Ollama or OpenAI)."""
    import httpx

    # Try Ollama first (local)
    ollama_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    try:
        async with httpx.AsyncClient(timeout=VISION_TIMEOUT) as client:
            resp = await client.post(
                f"{ollama_url}/api/generate",
                json={
                    "model": VISION_MODEL,
                    "prompt": prompt,
                    "images": [image_b64],
                    "stream": False,
                    "options": {
                        "num_predict": VISION_MAX_TOKENS,
                    },
                },
            )

            if resp.status_code == 200:
                data = resp.json()
                return {"response": data.get("response", "")}
            else:
                log.warning("ollama_vision_failed", status=resp.status_code)

    except Exception as e:
        log.warning("ollama_vision_error", error=str(e))

    # Fallback to OpenAI if configured
    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        try:
            async with httpx.AsyncClient(timeout=VISION_TIMEOUT) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {openai_key}"},
                    json={
                        "model": "gpt-4-vision-preview",
                        "messages": [
                            {
                                "role": "user",
                                "content": [
                                    {"type": "text", "text": prompt},
                                    {
                                        "type": "image_url",
                                        "image_url": {"url": f"data:image/png;base64,{image_b64}"},
                                    },
                                ],
                            }
                        ],
                        "max_tokens": VISION_MAX_TOKENS,
                    },
                )

                if resp.status_code == 200:
                    data = resp.json()
                    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                    return {"response": content}

        except Exception as e:
            log.warning("openai_vision_error", error=str(e))

    return {"error": "Vision model not available. Configure OLLAMA_HOST or OPENAI_API_KEY."}


@tool(
    name="compare_before_after_screenshots",
    description="Compare before and after screenshots to validate exploitation evidence.",
)
async def compare_before_after_screenshots(
    before_path: str,
    after_path: str,
    vuln_type: str,
    expected_change: str,
    original_finding: str = "",
) -> str:
    """
    Compare before/after screenshots for verification.

    Args:
        before_path: Path to "before" screenshot
        after_path: Path to "after" screenshot
        vuln_type: Type of vulnerability
        expected_change: What change we expect to see
        original_finding: Original finding description
    """
    if not os.path.exists(before_path):
        return json.dumps({"error": f"Before screenshot not found: {before_path}"})
    if not os.path.exists(after_path):
        return json.dumps({"error": f"After screenshot not found: {after_path}"})

    try:
        # Load both images
        before_b64 = _load_image_as_base64(before_path)
        after_b64 = _load_image_as_base64(after_path)

        # Build comparison prompt
        prompt = EVIDENCE_COMPARISON_PROMPT.format(
            vuln_type=vuln_type,
            expected_change=expected_change,
            original_finding=original_finding,
        )

        # For Ollama, we need to send both images
        # This is a simplified version - sending after image with context about before
        comparison_prompt = f"""
{prompt}

I'm providing two screenshots:
1. BEFORE screenshot (first image)
2. AFTER screenshot (second image)

Please compare them and analyze the differences.
"""

        # Call vision model with both images
        result = await _call_vision_model_multi(comparison_prompt, [before_b64, after_b64])

        if "error" in result:
            return json.dumps(result)

        analysis = _parse_json_from_response(result.get("response", ""))

        if not analysis:
            analysis = {
                "exploitation_evident": False,
                "confidence": 0.0,
                "verification_status": "inconclusive",
                "notes": result.get("response", "Unable to parse response"),
            }

        analysis["before_path"] = before_path
        analysis["after_path"] = after_path

        return json.dumps(analysis)

    except Exception as e:
        log.error("screenshot_comparison_failed", error=str(e))
        return json.dumps({"error": str(e)})


async def _call_vision_model_multi(prompt: str, images_b64: list[str]) -> dict[str, Any]:
    """Call vision model with multiple images."""
    import httpx

    ollama_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    try:
        async with httpx.AsyncClient(timeout=VISION_TIMEOUT) as client:
            resp = await client.post(
                f"{ollama_url}/api/generate",
                json={
                    "model": VISION_MODEL,
                    "prompt": prompt,
                    "images": images_b64,
                    "stream": False,
                    "options": {"num_predict": VISION_MAX_TOKENS},
                },
            )

            if resp.status_code == 200:
                return {"response": resp.json().get("response", "")}

    except Exception as e:
        log.warning("vision_multi_image_error", error=str(e))

    return {"error": "Multi-image vision analysis not available"}


@tool(
    name="detect_false_positive",
    description="Analyze finding for false positive indicators using pattern matching and heuristics.",
)
async def detect_false_positive(
    finding_type: str,
    response_content: str,
    response_headers: dict[str, str] | None = None,
    payload_reflected: bool = False,
) -> str:
    """
    Detect potential false positives.

    Args:
        finding_type: Type of finding (xss, sqli, rce, etc.)
        response_content: Response content to analyze
        response_headers: Response headers
        payload_reflected: Whether payload was reflected in response
    """
    response_headers = response_headers or {}
    indicators: list[dict[str, Any]] = []
    false_positive_score = 0.0

    finding_type_lower = finding_type.lower()

    # XSS false positive detection
    if finding_type_lower == "xss":
        # Check if payload is HTML-encoded
        if payload_reflected:
            encoded_patterns = ["&lt;", "&gt;", "&#", "&amp;"]
            if any(p in response_content for p in encoded_patterns):
                indicators.append({
                    "type": "encoded_output",
                    "description": "Payload appears HTML-encoded",
                    "confidence": 0.8,
                })
                false_positive_score += 0.4

        # Check Content-Type
        content_type = response_headers.get("content-type", "").lower()
        if "application/json" in content_type:
            indicators.append({
                "type": "json_response",
                "description": "Response is JSON, not rendered HTML",
                "confidence": 0.6,
            })
            false_positive_score += 0.3

    # SQLi false positive detection
    if finding_type_lower == "sqli":
        # Check for generic error pages
        generic_errors = ["error occurred", "something went wrong", "please try again"]
        if any(e in response_content.lower() for e in generic_errors):
            indicators.append({
                "type": "generic_error",
                "description": "Generic error page, not SQL-specific",
                "confidence": 0.5,
            })
            false_positive_score += 0.2

        # Check for WAF blocking
        waf_patterns = ["blocked", "forbidden", "access denied", "firewall"]
        if any(p in response_content.lower() for p in waf_patterns):
            indicators.append({
                "type": "waf_blocked",
                "description": "Response suggests WAF blocking",
                "confidence": 0.7,
            })
            false_positive_score += 0.3

    # RCE false positive detection
    if finding_type_lower in ("rce", "cmdi"):
        # Check if output is actually command output
        if not any(p in response_content for p in ["uid=", "root", "/bin", "total "]):
            indicators.append({
                "type": "no_command_output",
                "description": "No recognizable command output",
                "confidence": 0.6,
            })
            false_positive_score += 0.3

    # Rate limiting detection
    if "rate limit" in response_content.lower() or "too many requests" in response_content.lower():
        indicators.append({
            "type": "rate_limited",
            "description": "Response indicates rate limiting",
            "confidence": 0.9,
        })
        false_positive_score += 0.4

    false_positive_score = min(false_positive_score, 1.0)

    return json.dumps({
        "finding_type": finding_type,
        "false_positive_probability": round(false_positive_score, 2),
        "likely_false_positive": false_positive_score >= FALSE_POSITIVE_THRESHOLD,
        "indicators": indicators,
        "recommendation": (
            "Mark as false positive" if false_positive_score >= 0.8
            else "Needs manual review" if false_positive_score >= 0.5
            else "Likely true positive"
        ),
    })
