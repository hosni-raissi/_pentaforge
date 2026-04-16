"""Curated retest command catalog for `run_custom` usage."""

from __future__ import annotations

RETEST_TOOLS: dict[str, dict[str, object]] = {
    "curl": {
        "t": "http",
        "c": "payload_replay",
        "u": "curl -i -sS TARGET",
        "d": ["replay requests", "header/status comparison"],
        "tgt": ["http", "api"],
    },
    "ffuf": {
        "t": "fuzzing",
        "c": "bypass_probe",
        "u": "ffuf -u TARGET/FUZZ -w WORDLIST -mc all -fc 404",
        "d": ["mutation bypass checks", "parameter/path variant probing"],
        "tgt": ["web", "api"],
    },
    "sqlmap": {
        "t": "injection",
        "c": "sqli_retest",
        "u": "sqlmap -u TARGET --batch --risk=1 --level=1",
        "d": ["post-fix SQLi replay", "regression check"],
        "tgt": ["web", "api"],
    },
    "nuclei": {
        "t": "template_scan",
        "c": "regression_validation",
        "u": "nuclei -u TARGET -severity critical,high,medium",
        "d": ["known issue regression checks"],
        "tgt": ["web", "api", "network"],
    },
    "jq": {
        "t": "analysis",
        "c": "response_diff",
        "u": "jq . FILE.json",
        "d": ["JSON diff parsing", "field-level response validation"],
        "tgt": ["api", "json"],
    },
}

