"""Bypass mutation tools for Retest agent."""

from __future__ import annotations

import base64
import json
import urllib.parse
from typing import Any

import structlog

from server.core.tool import tool
from server.core.llm import call_llm
from ..config import (
    USE_LLM_MUTATIONS,
    MAX_MUTATIONS_PER_PAYLOAD,
    MUTATION_STRATEGIES,
    ENCODING_CHAINS,
)
from ..prompts import MUTATION_GENERATION_PROMPT

log = structlog.get_logger(__name__)


@tool(
    name="generate_mutations",
    description="Generate bypass mutations for a blocked payload using various techniques.",
)
async def generate_mutations(
    original_payload: str,
    vuln_type: str,
    block_reason: str = "",
    tech_stack: str = "",
    num_mutations: int = 10,
) -> str:
    """
    Generate mutation variants of a payload to bypass protections.

    Args:
        original_payload: The original payload that was blocked
        vuln_type: Type of vulnerability (sqli, xss, rce, etc.)
        block_reason: Why the payload was blocked (if known)
        tech_stack: Target technology stack
        num_mutations: Number of mutations to generate
    """
    mutations = []

    # Generate encoding-based mutations
    for chain in ENCODING_CHAINS:
        encoded = _apply_encoding_chain(original_payload, chain)
        if encoded != original_payload:
            mutations.append({
                "payload": encoded,
                "technique": "encoding_chain",
                "description": f"Encoding: {' -> '.join(chain)}",
                "confidence": 0.6,
            })

    # Generate case variations
    case_mutations = _generate_case_mutations(original_payload, vuln_type)
    mutations.extend(case_mutations)

    # Generate whitespace mutations
    whitespace_mutations = _generate_whitespace_mutations(original_payload, vuln_type)
    mutations.extend(whitespace_mutations)

    # Generate comment injection mutations
    comment_mutations = _generate_comment_mutations(original_payload, vuln_type)
    mutations.extend(comment_mutations)

    # Generate null byte mutations
    null_mutations = _generate_null_byte_mutations(original_payload)
    mutations.extend(null_mutations)

    # Generate syntax variation mutations
    syntax_mutations = _generate_syntax_variations(original_payload, vuln_type)
    mutations.extend(syntax_mutations)

    # Limit to requested number
    mutations = mutations[:num_mutations]

    return json.dumps({
        "original_payload": original_payload,
        "vuln_type": vuln_type,
        "num_mutations": len(mutations),
        "mutations": mutations,
        "strategies_used": list(set(m["technique"] for m in mutations)),
    })


@tool(
    name="llm_generate_mutations",
    description="Use LLM to generate intelligent bypass mutations based on context.",
)
async def llm_generate_mutations(
    original_payload: str,
    vuln_type: str,
    block_reason: str = "",
    tech_stack: str = "",
    waf_info: str = "",
    num_mutations: int = 5,
) -> str:
    """
    Use LLM to generate context-aware bypass mutations.

    Args:
        original_payload: The blocked payload
        vuln_type: Type of vulnerability
        block_reason: Why the payload was blocked
        tech_stack: Target technology (PHP, Java, Node, etc.)
        waf_info: WAF/filter information if known
        num_mutations: Number of mutations to request
    """
    if not USE_LLM_MUTATIONS:
        return json.dumps({
            "error": "LLM mutations disabled in config",
            "fallback": "Use generate_mutations for rule-based mutations",
        })

    prompt = MUTATION_GENERATION_PROMPT.format(
        vuln_type=vuln_type,
        original_payload=original_payload,
        block_reason=block_reason or "Unknown",
        tech_stack=tech_stack or "Unknown",
        waf_info=waf_info or "Unknown",
        num_mutations=num_mutations,
    )

    try:
        response = await call_llm(
            prompt=prompt,
            system="You are a security testing expert specializing in WAF bypass techniques. Generate creative but realistic payload mutations.",
            temperature=0.7,
        )

        # Parse LLM response
        result = json.loads(response)
        return json.dumps({
            "original_payload": original_payload,
            "vuln_type": vuln_type,
            "llm_generated": True,
            "mutations": result.get("mutations", []),
            "reasoning": result.get("reasoning", ""),
        })

    except Exception as e:
        log.warning("llm_mutation_failed", error=str(e))
        # Fallback to rule-based mutations
        return await generate_mutations(
            original_payload=original_payload,
            vuln_type=vuln_type,
            block_reason=block_reason,
            tech_stack=tech_stack,
            num_mutations=num_mutations,
        )


@tool(
    name="apply_encoding_chain",
    description="Apply a specific encoding chain to a payload.",
)
async def apply_encoding_chain(
    payload: str,
    encodings: str,
) -> str:
    """
    Apply encoding chain to payload.

    Args:
        payload: Original payload
        encodings: JSON array of encodings ["url", "base64", "hex"]
    """
    try:
        encoding_list = json.loads(encodings)
    except json.JSONDecodeError:
        encoding_list = encodings.split(",")

    encoded = _apply_encoding_chain(payload, encoding_list)

    return json.dumps({
        "original": payload,
        "encoded": encoded,
        "encodings_applied": encoding_list,
    })


def _apply_encoding_chain(payload: str, chain: list[str]) -> str:
    """Apply a chain of encodings to payload."""
    result = payload
    for encoding in chain:
        encoding = encoding.lower().strip()
        if encoding == "url":
            result = urllib.parse.quote(result, safe="")
        elif encoding == "base64":
            result = base64.b64encode(result.encode()).decode()
        elif encoding == "unicode":
            result = "".join(f"\\u{ord(c):04x}" for c in result)
        elif encoding == "hex":
            result = "".join(f"\\x{ord(c):02x}" for c in result)
        elif encoding == "html":
            result = "".join(f"&#{ord(c)};" for c in result)
    return result


def _generate_case_mutations(payload: str, vuln_type: str) -> list[dict]:
    """Generate case variation mutations."""
    mutations = []

    # Upper case
    mutations.append({
        "payload": payload.upper(),
        "technique": "case_variation",
        "description": "All uppercase",
        "confidence": 0.4,
    })

    # Mixed case for keywords
    if vuln_type in ["sqli", "xss"]:
        mixed = ""
        for i, c in enumerate(payload):
            mixed += c.upper() if i % 2 == 0 else c.lower()
        mutations.append({
            "payload": mixed,
            "technique": "case_variation",
            "description": "Alternating case",
            "confidence": 0.5,
        })

    return mutations


def _generate_whitespace_mutations(payload: str, vuln_type: str) -> list[dict]:
    """Generate whitespace injection mutations."""
    mutations = []

    # Tab injection
    mutations.append({
        "payload": payload.replace(" ", "\t"),
        "technique": "whitespace",
        "description": "Spaces replaced with tabs",
        "confidence": 0.5,
    })

    # Newline injection
    mutations.append({
        "payload": payload.replace(" ", "\n"),
        "technique": "whitespace",
        "description": "Spaces replaced with newlines",
        "confidence": 0.4,
    })

    # Multiple spaces
    mutations.append({
        "payload": payload.replace(" ", "  "),
        "technique": "whitespace",
        "description": "Double spaces",
        "confidence": 0.3,
    })

    return mutations


def _generate_comment_mutations(payload: str, vuln_type: str) -> list[dict]:
    """Generate comment injection mutations."""
    mutations = []

    if vuln_type == "sqli":
        # SQL inline comments
        mutations.append({
            "payload": payload.replace(" ", "/**/"),
            "technique": "comment_injection",
            "description": "SQL inline comments",
            "confidence": 0.7,
        })
        # MySQL specific
        mutations.append({
            "payload": payload.replace(" ", "/*!*/"),
            "technique": "comment_injection",
            "description": "MySQL version comments",
            "confidence": 0.6,
        })

    elif vuln_type == "xss":
        # HTML comments
        mutations.append({
            "payload": payload.replace(">", "><!---->"),
            "technique": "comment_injection",
            "description": "HTML comment injection",
            "confidence": 0.5,
        })

    return mutations


def _generate_null_byte_mutations(payload: str) -> list[dict]:
    """Generate null byte injection mutations."""
    return [
        {
            "payload": payload + "%00",
            "technique": "null_byte",
            "description": "Trailing null byte (URL encoded)",
            "confidence": 0.5,
        },
        {
            "payload": "%00" + payload,
            "technique": "null_byte",
            "description": "Leading null byte",
            "confidence": 0.4,
        },
    ]


def _generate_syntax_variations(payload: str, vuln_type: str) -> list[dict]:
    """Generate syntax variation mutations."""
    mutations = []

    if vuln_type == "sqli":
        # OR variations
        if " or " in payload.lower():
            mutations.append({
                "payload": payload.replace(" or ", " || "),
                "technique": "syntax_variation",
                "description": "OR to || operator",
                "confidence": 0.6,
            })
        # AND variations
        if " and " in payload.lower():
            mutations.append({
                "payload": payload.replace(" and ", " && "),
                "technique": "syntax_variation",
                "description": "AND to && operator",
                "confidence": 0.6,
            })
        # Quote variations
        if "'" in payload:
            mutations.append({
                "payload": payload.replace("'", "\""),
                "technique": "syntax_variation",
                "description": "Single to double quotes",
                "confidence": 0.5,
            })

    elif vuln_type == "xss":
        # Event handler variations
        if "onerror" in payload.lower():
            mutations.append({
                "payload": payload.replace("onerror", "onload"),
                "technique": "syntax_variation",
                "description": "onerror to onload",
                "confidence": 0.6,
            })
        # Tag variations
        if "<script" in payload.lower():
            mutations.append({
                "payload": payload.replace("<script", "<svg/onload"),
                "technique": "syntax_variation",
                "description": "Script to SVG onload",
                "confidence": 0.7,
            })
            mutations.append({
                "payload": payload.replace("<script", "<img src=x onerror"),
                "technique": "syntax_variation",
                "description": "Script to IMG onerror",
                "confidence": 0.7,
            })

    return mutations
