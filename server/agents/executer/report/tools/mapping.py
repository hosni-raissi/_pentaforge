"""OWASP and MITRE ATT&CK mapping tools for Report agent."""

from __future__ import annotations

import json
from typing import Any

import structlog

from server.core.tool import tool
from ..config import OWASP_TOP_10_2021, VULN_TO_OWASP, VULN_TO_MITRE

log = structlog.get_logger(__name__)

# CWE mappings for common vulnerabilities
CWE_MAPPINGS = {
    "sqli": {"id": "CWE-89", "name": "SQL Injection"},
    "xss": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)"},
    "xss_stored": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)"},
    "xss_reflected": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)"},
    "xss_dom": {"id": "CWE-79", "name": "Cross-site Scripting (XSS)"},
    "cmdi": {"id": "CWE-78", "name": "OS Command Injection"},
    "rce": {"id": "CWE-94", "name": "Code Injection"},
    "ssrf": {"id": "CWE-918", "name": "Server-Side Request Forgery"},
    "idor": {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key"},
    "path_traversal": {"id": "CWE-22", "name": "Path Traversal"},
    "lfi": {"id": "CWE-98", "name": "PHP Remote File Inclusion"},
    "rfi": {"id": "CWE-98", "name": "PHP Remote File Inclusion"},
    "xxe": {"id": "CWE-611", "name": "XML External Entity Reference"},
    "ssti": {"id": "CWE-1336", "name": "Server-Side Template Injection"},
    "csrf": {"id": "CWE-352", "name": "Cross-Site Request Forgery"},
    "auth_bypass": {"id": "CWE-287", "name": "Improper Authentication"},
    "broken_auth": {"id": "CWE-287", "name": "Improper Authentication"},
    "session_fixation": {"id": "CWE-384", "name": "Session Fixation"},
    "insecure_deserialization": {"id": "CWE-502", "name": "Deserialization of Untrusted Data"},
    "file_upload": {"id": "CWE-434", "name": "Unrestricted Upload of Dangerous File Type"},
    "open_redirect": {"id": "CWE-601", "name": "URL Redirection to Untrusted Site"},
    "hardcoded_secrets": {"id": "CWE-798", "name": "Hardcoded Credentials"},
    "crypto_weakness": {"id": "CWE-327", "name": "Use of Broken Crypto Algorithm"},
    "misconfig": {"id": "CWE-16", "name": "Configuration"},
    "info_disclosure": {"id": "CWE-200", "name": "Information Exposure"},
    "buffer_overflow": {"id": "CWE-120", "name": "Buffer Overflow"},
    "race_condition": {"id": "CWE-362", "name": "Race Condition"},
}

# MITRE ATT&CK technique details
MITRE_TECHNIQUES = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1189": {"name": "Drive-by Compromise", "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "Execution"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1530": {"name": "Data from Cloud Storage Object", "tactic": "Collection"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
}


@tool(
    name="map_to_owasp",
    description="Map a vulnerability type to OWASP Top 10 2021 category.",
)
async def map_to_owasp(
    vuln_type: str,
    vuln_details: str = "",
) -> str:
    """
    Map vulnerability to OWASP Top 10 2021.

    Args:
        vuln_type: Type of vulnerability (sqli, xss, rce, ssrf, etc.)
        vuln_details: Additional details for context-aware mapping
    """
    vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")

    # Direct mapping
    owasp_id = VULN_TO_OWASP.get(vuln_type)

    # Fuzzy matching if no direct match
    if not owasp_id:
        for key, value in VULN_TO_OWASP.items():
            if key in vuln_type or vuln_type in key:
                owasp_id = value
                break

    # Default to A05 (Security Misconfiguration) if unknown
    if not owasp_id:
        owasp_id = "A05"

    owasp_name = OWASP_TOP_10_2021.get(owasp_id, "Unknown")

    return json.dumps({
        "vuln_type": vuln_type,
        "owasp": {
            "id": owasp_id,
            "name": owasp_name,
            "year": 2021,
            "url": f"https://owasp.org/Top10/A{owasp_id[1:]}_{owasp_name.replace(' ', '_')}/"
        }
    })


@tool(
    name="map_to_mitre",
    description="Map a vulnerability type to MITRE ATT&CK techniques.",
)
async def map_to_mitre(
    vuln_type: str,
    attack_context: str = "",
) -> str:
    """
    Map vulnerability to MITRE ATT&CK techniques.

    Args:
        vuln_type: Type of vulnerability
        attack_context: Context of the attack for better mapping
    """
    vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")

    # Get technique IDs
    technique_ids = VULN_TO_MITRE.get(vuln_type, ["T1190"])

    # Fuzzy matching
    if vuln_type not in VULN_TO_MITRE:
        for key, value in VULN_TO_MITRE.items():
            if key in vuln_type or vuln_type in key:
                technique_ids = value
                break

    # Build technique details
    techniques = []
    for tid in technique_ids:
        if tid in MITRE_TECHNIQUES:
            techniques.append({
                "id": tid,
                "name": MITRE_TECHNIQUES[tid]["name"],
                "tactic": MITRE_TECHNIQUES[tid]["tactic"],
                "url": f"https://attack.mitre.org/techniques/{tid}/"
            })
        else:
            techniques.append({
                "id": tid,
                "name": "Unknown Technique",
                "tactic": "Unknown",
                "url": f"https://attack.mitre.org/techniques/{tid}/"
            })

    return json.dumps({
        "vuln_type": vuln_type,
        "mitre_attack": {
            "version": "14.1",
            "techniques": techniques
        }
    })


@tool(
    name="map_to_cwe",
    description="Map a vulnerability type to CWE identifier.",
)
async def map_to_cwe(
    vuln_type: str,
) -> str:
    """
    Map vulnerability to CWE identifier.

    Args:
        vuln_type: Type of vulnerability
    """
    vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")

    # Direct mapping
    cwe = CWE_MAPPINGS.get(vuln_type)

    # Fuzzy matching
    if not cwe:
        for key, value in CWE_MAPPINGS.items():
            if key in vuln_type or vuln_type in key:
                cwe = value
                break

    # Default
    if not cwe:
        cwe = {"id": "CWE-1035", "name": "OWASP Top Ten 2017 Category A10"}

    return json.dumps({
        "vuln_type": vuln_type,
        "cwe": {
            "id": cwe["id"],
            "name": cwe["name"],
            "url": f"https://cwe.mitre.org/data/definitions/{cwe['id'].split('-')[1]}.html"
        }
    })


@tool(
    name="get_full_mapping",
    description="Get complete security framework mapping for a vulnerability.",
)
async def get_full_mapping(
    vuln_type: str,
    severity: str = "medium",
    details: str = "",
) -> str:
    """
    Get complete mapping to OWASP, MITRE, and CWE.

    Args:
        vuln_type: Type of vulnerability
        severity: Vulnerability severity
        details: Additional details
    """
    vuln_type = vuln_type.lower().replace(" ", "_").replace("-", "_")

    # Get OWASP mapping
    owasp_id = VULN_TO_OWASP.get(vuln_type, "A05")
    owasp_name = OWASP_TOP_10_2021.get(owasp_id, "Security Misconfiguration")

    # Get MITRE mapping
    technique_ids = VULN_TO_MITRE.get(vuln_type, ["T1190"])
    techniques = []
    for tid in technique_ids:
        if tid in MITRE_TECHNIQUES:
            techniques.append({
                "id": tid,
                "name": MITRE_TECHNIQUES[tid]["name"],
                "tactic": MITRE_TECHNIQUES[tid]["tactic"],
            })

    # Get CWE mapping
    cwe = CWE_MAPPINGS.get(vuln_type, {"id": "CWE-1035", "name": "Unknown"})

    return json.dumps({
        "vuln_type": vuln_type,
        "severity": severity,
        "owasp": {
            "id": owasp_id,
            "name": owasp_name,
            "year": 2021
        },
        "mitre_attack": {
            "techniques": techniques
        },
        "cwe": cwe,
        "compliance": {
            "pci_dss": _get_pci_mapping(vuln_type),
            "gdpr": _get_gdpr_relevance(vuln_type),
        }
    })


def _get_pci_mapping(vuln_type: str) -> list[str]:
    """Get PCI DSS requirements related to vulnerability."""
    mappings = {
        "sqli": ["6.5.1", "6.6"],
        "xss": ["6.5.7", "6.6"],
        "auth_bypass": ["8.1", "8.2"],
        "crypto_weakness": ["3.4", "4.1"],
        "hardcoded_secrets": ["3.6", "8.2.1"],
        "misconfig": ["2.1", "2.2"],
    }
    return mappings.get(vuln_type, ["6.5"])


def _get_gdpr_relevance(vuln_type: str) -> dict[str, Any]:
    """Get GDPR relevance for vulnerability."""
    high_risk = ["sqli", "rce", "auth_bypass", "idor", "xxe", "ssrf"]
    medium_risk = ["xss", "csrf", "path_traversal", "info_disclosure"]

    if vuln_type in high_risk:
        return {
            "relevant": True,
            "risk_level": "high",
            "articles": ["Article 32", "Article 33", "Article 34"],
            "note": "May require breach notification if exploited"
        }
    elif vuln_type in medium_risk:
        return {
            "relevant": True,
            "risk_level": "medium",
            "articles": ["Article 32"],
            "note": "Security measure deficiency"
        }
    return {
        "relevant": False,
        "risk_level": "low",
        "articles": [],
        "note": "Limited GDPR relevance"
    }
