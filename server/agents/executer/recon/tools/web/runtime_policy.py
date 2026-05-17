"""Runtime policy for incremental web recon migration.

This module keeps the current approach explicit:
- keep smart Python web recon tools active
- expose wrapper replacements only when a real alias-backed path exists
- treat the run_custom security catalog as supplemental, not a bulk replacement
"""

from __future__ import annotations

WEB_ALIAS_MODULES: tuple[str, ...] = (
    "web.security_tool_aliases",
)

WEB_ALIAS_BACKED_TOOL_NAMES: tuple[str, ...] = (
    "cms_detect_and_scan",
    "directory_file_fuzzing",
    "http_probe",
)

WEB_SMART_PYTHON_MODULES: tuple[str, ...] = (
    "web.cors_misconfig_check",
    "web.js_source_code_analyzer",
    "web.passive_web_recon",
    "web.session_token_analysis",
    "web.websocket_recon",
)

WEB_SMART_PYTHON_TOOL_NAMES: tuple[str, ...] = (
    "cors_misconfig_check",
    "js_source_code_analyzer",
    "passive_web_recon",
    "session_token_analysis",
    "websocket_recon",
)

WEB_RECON_RUNTIME_POLICY: dict[str, object] = {
    "migration_mode": "incremental",
    "keep_smart_python_tools": list(WEB_SMART_PYTHON_TOOL_NAMES),
    "alias_backed_wrappers": list(WEB_ALIAS_BACKED_TOOL_NAMES),
    "notes": [
        "Do not bulk-delete smart Python tools just because a matching CLI exists in the security catalog.",
        "Only remove a wrapper after a real alias-backed or router-backed replacement is active in runtime loading.",
        "Treat security_tools.py as a supplemental run_custom catalog, not as a one-for-one replacement map.",
    ],
}


def load_web_recon_runtime_policy() -> dict[str, object]:
    """Return a copy-safe view of the current web recon migration policy."""
    return {
        "migration_mode": WEB_RECON_RUNTIME_POLICY["migration_mode"],
        "keep_smart_python_tools": list(WEB_SMART_PYTHON_TOOL_NAMES),
        "alias_backed_wrappers": list(WEB_ALIAS_BACKED_TOOL_NAMES),
        "notes": list(WEB_RECON_RUNTIME_POLICY["notes"]),
    }
