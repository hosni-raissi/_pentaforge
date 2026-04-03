"""Recon tool registry."""

from server.core.tool import Tool

# Port scanning tools
from .port_scanner import port_scan, fast_port_scan, service_probe

# Subdomain enumeration tools
from .subdomain_enum import enumerate_subdomains, dns_records

# Stealth analysis tools
from .stealth_analyzer import analyze_stealth, adaptive_scan_delay, check_waf_detection

# Technology detection tools
from .tech_detection import detect_technologies, http_probe

# OSINT and secret discovery tools
from .osint import osint_search, discover_secrets, search_github_code, check_breach_database

# Legacy tool (keep for backwards compatibility)
from .record_recon_signal import record_recon_signal

# Vulnerability scanning tools
from .vuln_scanner import (
    vuln_scan,
    nikto_scan,
    network_vuln_scan,
    ssl_tls_analysis,
)

# Exploit search and credential brute force tools
from .exploit_search import (
    exploit_search,
    exploit_search_by_cve,
    exploit_search_by_service,
    exploit_copy,
    credential_brute,
    snmp_brute,
)

# Web scanning and fuzzing tools
from .web_scanner import (
    http_probe as httpx_probe,
    waf_detection,
    directory_file_fuzzing,
    web_fuzz,
    web_crawler,
    param_discovery,
    js_source_code_analyzer,
    cms_detect_and_scan,
)

# Network reconnaissance tools
from .network_recon import (
    network_enum,
    osint_gather,
    screenshot_capture,
    dns_enum_fuzzing,
)

# Security checks tools
from .security_checks import (
    cors_misconfig_check,
    http_header_analysis,
    subdomain_takeover_check,
    vhost_discovery,
    cdn_origin_detect,
    linux_privesc_audit,
)


ALL_RECON_TOOLS: list[Tool] = [
    # Port scanning
    port_scan,
    fast_port_scan,
    service_probe,
    # Subdomain enumeration
    enumerate_subdomains,
    dns_records,
    # Stealth analysis
    analyze_stealth,
    adaptive_scan_delay,
    check_waf_detection,
    # Technology detection
    detect_technologies,
    http_probe,
    # OSINT and secrets
    osint_search,
    discover_secrets,
    search_github_code,
    check_breach_database,
    # Vulnerability scanning
    vuln_scan,
    nikto_scan,
    network_vuln_scan,
    ssl_tls_analysis,
    # Exploit search & credential brute force
    exploit_search,
    exploit_search_by_cve,
    exploit_search_by_service,
    exploit_copy,
    credential_brute,
    snmp_brute,
    # Web scanning & fuzzing
    httpx_probe,
    waf_detection,
    directory_file_fuzzing,
    web_fuzz,
    web_crawler,
    param_discovery,
    js_source_code_analyzer,
    cms_detect_and_scan,
    # Network reconnaissance
    network_enum,
    osint_gather,
    screenshot_capture,
    dns_enum_fuzzing,
    # Security checks
    cors_misconfig_check,
    http_header_analysis,
    subdomain_takeover_check,
    vhost_discovery,
    cdn_origin_detect,
    linux_privesc_audit,
    # Legacy
    record_recon_signal,
]

__all__ = [
    "ALL_RECON_TOOLS",
    # Port scanning
    "port_scan",
    "fast_port_scan",
    "service_probe",
    # Subdomain enumeration
    "enumerate_subdomains",
    "dns_records",
    # Stealth analysis
    "analyze_stealth",
    "adaptive_scan_delay",
    "check_waf_detection",
    # Technology detection
    "detect_technologies",
    "http_probe",
    # OSINT
    "osint_search",
    "discover_secrets",
    "search_github_code",
    "check_breach_database",
    # Vulnerability scanning
    "vuln_scan",
    "nikto_scan",
    "network_vuln_scan",
    "ssl_tls_analysis",
    # Exploit search & credential brute force
    "exploit_search",
    "exploit_search_by_cve",
    "exploit_search_by_service",
    "exploit_copy",
    "credential_brute",
    "snmp_brute",
    # Web scanning & fuzzing
    "httpx_probe",
    "waf_detection",
    "directory_file_fuzzing",
    "web_fuzz",
    "web_crawler",
    "param_discovery",
    "js_source_code_analyzer",
    "cms_detect_and_scan",
    # Network reconnaissance
    "network_enum",
    "osint_gather",
    "screenshot_capture",
    "dns_enum_fuzzing",
    # Security checks
    "cors_misconfig_check",
    "http_header_analysis",
    "subdomain_takeover_check",
    "vhost_discovery",
    "cdn_origin_detect",
    "linux_privesc_audit",
    # Legacy
    "record_recon_signal",
]
