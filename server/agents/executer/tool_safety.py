"""Execution safety profiles for executer tools and run_custom commands."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

SafetyCategory = Literal["passive_recon", "active_scan", "exploitation", "destructive"]
RiskLevel = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class ToolSafetyProfile:
    name: str
    category: SafetyCategory
    risk_level: RiskLevel
    requires_human_approval: bool
    isolated_execution: bool = True
    outbound_network: bool = True
    filesystem_write_policy: str = "sandbox_only"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_LOW_RISK_TOOL_NAMES = {
    "http_probe",
    "http_header_analysis",
    "detect_tech",
    "web_crawler",
    "api_passive_enum",
    "api_response_analyzer",
    "js_source_code_analyzer",
    "known_vuln_lookup",
    "param_discovery",
    "graphql_recon",
    "grpc_recon",
    "soap_wsdl_recon",
    "oauth_oidc_check",
}

_MEDIUM_RISK_TOOL_NAMES = {
    "directory_file_fuzzing",
    "dns_recon",
    "ssl_tls_analysis",
    "route_topology",
    "traffic_analyze",
    "wireless_scan",
    "nuclei_vuln_scan",
}

_HIGH_RISK_TOOL_NAMES = {
    "api_payload_injection",
    "api_abuse_test",
    "api_auth_test",
    "api_authz_matrix",
    "api_fuzzing",
    "db_injection_test",
    "file_upload_api_abuse",
    "graphql_attack",
    "http_smuggling",
    "jwt_attack",
    "nosql_injection_test",
    "open_redirect_scan",
    "prompt_injection_test",
    "race_condition_test",
    "script_injection_test",
    "ssrf_detect",
    "ssti_detect",
    "web_auth_brute",
    "web_payload_injection",
    "webhook_security_test",
    "websocket_attack",
    "xss_scan",
    "run_python",
}

_CRITICAL_TOOL_NAMES = {
    "hydra_bruteforce",
    "john_the_ripper_bruteforce",
    "metasploit_exploit",
    "payload_generator",
    "sqlmap_injection",
    "run_custom",
}

_PASSIVE_COMMANDS = {
    "curl",
    "dig",
    "host",
    "nslookup",
    "openssl",
    "whatweb",
    "wget",
}

_ACTIVE_SCAN_COMMANDS = {
    "ffuf",
    "gobuster",
    "naabu",
    "nikto",
    "nmap",
    "nuclei",
    "wpscan",
    "zgrab2",
}

_EXPLOITATION_COMMANDS = {
    "commix",
    "hydra",
    "john",
    "medusa",
    "msfconsole",
    "patator",
    "responder",
    "sqlmap",
}


def _build_profile(
    name: str,
    *,
    category: SafetyCategory,
    risk_level: RiskLevel,
    requires_human_approval: bool,
) -> ToolSafetyProfile:
    return ToolSafetyProfile(
        name=name,
        category=category,
        risk_level=risk_level,
        requires_human_approval=requires_human_approval,
    )


def get_tool_safety_profile(tool_name: str, *, role: str = "") -> ToolSafetyProfile:
    clean_name = str(tool_name or "").strip().lower()
    clean_role = str(role or "").strip().lower()

    if clean_name in _CRITICAL_TOOL_NAMES:
        return _build_profile(clean_name, category="exploitation", risk_level="critical", requires_human_approval=True)
    if clean_name in _HIGH_RISK_TOOL_NAMES:
        return _build_profile(clean_name, category="exploitation", risk_level="high", requires_human_approval=True)
    if clean_name in _MEDIUM_RISK_TOOL_NAMES:
        return _build_profile(clean_name, category="active_scan", risk_level="medium", requires_human_approval=False)
    if clean_name in _LOW_RISK_TOOL_NAMES:
        return _build_profile(clean_name, category="passive_recon", risk_level="low", requires_human_approval=False)

    if clean_role == "exploit":
        return _build_profile(clean_name or "unknown", category="exploitation", risk_level="high", requires_human_approval=True)
    return _build_profile(clean_name or "unknown", category="active_scan", risk_level="medium", requires_human_approval=False)


def get_run_custom_command_profile(command: str, *, role: str = "") -> ToolSafetyProfile:
    clean_command = str(command or "").strip().lower()
    if clean_command in _EXPLOITATION_COMMANDS:
        return _build_profile(clean_command or "run_custom", category="exploitation", risk_level="critical", requires_human_approval=True)
    if clean_command in _ACTIVE_SCAN_COMMANDS:
        return _build_profile(clean_command or "run_custom", category="active_scan", risk_level="high", requires_human_approval=True)
    if clean_command in _PASSIVE_COMMANDS:
        return _build_profile(clean_command or "run_custom", category="passive_recon", risk_level="medium", requires_human_approval=False)
    if str(role or "").strip().lower() == "exploit":
        return _build_profile(clean_command or "run_custom", category="exploitation", risk_level="high", requires_human_approval=True)
    return _build_profile(clean_command or "run_custom", category="active_scan", risk_level="high", requires_human_approval=True)


def requires_approval_for_execution(
    *,
    profile: ToolSafetyProfile,
    approval_mode: str,
    role: str = "",
    tool_name: str = "",
) -> bool:
    clean_mode = str(approval_mode or "").strip().lower()
    clean_role = str(role or "").strip().lower()
    clean_tool_name = str(tool_name or profile.name).strip().lower()

    if clean_role == "exploit":
        return True
    if clean_tool_name == "run_python":
        return True
    if clean_mode != "auto":
        if clean_tool_name == "run_custom":
            return True
        return profile.requires_human_approval or profile.risk_level in {"high", "critical"}
    return profile.requires_human_approval or profile.risk_level == "critical"
