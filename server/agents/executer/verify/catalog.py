"""Curated verify command catalog for `run_custom` usage."""

from __future__ import annotations

VERIFY_TOOLS: dict[str, dict[str, object]] = {
    "curl": {
        "t": "http",
        "c": "response_verify",
        "u": "curl -i -sS TARGET",
        "d": ["response/header verification", "status/body evidence checks"],
        "tgt": ["web", "api"],
    },
    "playwright": {
        "t": "browser",
        "c": "ui_validation",
        "u": "playwright screenshot TARGET screenshot.png",
        "d": ["browser-level rendering checks", "visual verification"],
        "tgt": ["web"],
    },
    "nuclei": {
        "t": "template_scan",
        "c": "false_positive_recheck",
        "u": "nuclei -u TARGET -severity critical,high,medium",
        "d": ["independent validation", "known-pattern correlation"],
        "tgt": ["web", "api", "network"],
    },
    "jq": {
        "t": "analysis",
        "c": "json_evidence",
        "u": "jq . FILE.json",
        "d": ["parse API evidence payloads", "extract proof fields"],
        "tgt": ["api", "json"],
    },
    "openssl": {
        "t": "crypto",
        "c": "artifact_hash",
        "u": "openssl dgst -sha256 FILE",
        "d": ["evidence hashing", "chain integrity verification"],
        "tgt": ["evidence", "files"],
    },
}

