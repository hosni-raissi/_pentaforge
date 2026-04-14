"""Configuration for the Report executer agent."""

# ═══════════════════════════════════════════════════════════════════════════════
#  LLM Configuration
# ═══════════════════════════════════════════════════════════════════════════════

MAX_TOOL_ROUNDS = 8
LLM_CALL_TIMEOUT_SECONDS = 300
REPORT_CONTEXT_WINDOW_MAX_TOKENS = 12000

# ═══════════════════════════════════════════════════════════════════════════════
#  CVSS Configuration
# ═══════════════════════════════════════════════════════════════════════════════

CVSS_VERSION = "3.1"
CVSS_DEFAULT_SCOPE = "unchanged"  # unchanged or changed

# CVSS severity thresholds (v3.1)
CVSS_SEVERITY_THRESHOLDS = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
    "info": 0.0,
}

# ═══════════════════════════════════════════════════════════════════════════════
#  OWASP/MITRE Mapping
# ═══════════════════════════════════════════════════════════════════════════════

# OWASP Top 10 2021
OWASP_TOP_10_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

# Vulnerability to OWASP mapping
VULN_TO_OWASP = {
    "sqli": "A03",
    "xss": "A03",
    "cmdi": "A03",
    "ssti": "A03",
    "xxe": "A03",
    "ssrf": "A10",
    "idor": "A01",
    "auth_bypass": "A07",
    "broken_auth": "A07",
    "session_fixation": "A07",
    "csrf": "A01",
    "path_traversal": "A01",
    "file_upload": "A04",
    "crypto_weakness": "A02",
    "hardcoded_secrets": "A02",
    "insecure_deserialization": "A08",
    "outdated_component": "A06",
    "misconfig": "A05",
    "logging_failure": "A09",
}

# MITRE ATT&CK mapping (simplified)
VULN_TO_MITRE = {
    "sqli": ["T1190", "T1059"],  # Exploit Public-Facing, Command Execution
    "xss": ["T1189", "T1059"],  # Drive-by Compromise
    "cmdi": ["T1059"],  # Command and Scripting Interpreter
    "ssrf": ["T1190", "T1552"],  # Exploit, Unsecured Credentials
    "rce": ["T1059", "T1203"],  # Command Execution, Exploitation
    "auth_bypass": ["T1078"],  # Valid Accounts
    "idor": ["T1530"],  # Data from Cloud Storage
    "path_traversal": ["T1083", "T1005"],  # File Discovery, Data Collection
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Report Output Configuration
# ═══════════════════════════════════════════════════════════════════════════════

REPORT_OUTPUT_PATH = "/tmp/pentaforge/reports"
REPORT_FORMATS = ["pdf", "html", "sarif", "json"]

# PDF settings
PDF_TEMPLATE = "professional"  # professional, minimal, detailed
PDF_INCLUDE_EVIDENCE = True
PDF_INCLUDE_SCREENSHOTS = True
PDF_MAX_SCREENSHOT_SIZE = (800, 600)

# HTML settings
HTML_TEMPLATE = "modern"
HTML_INTERACTIVE = True

# SARIF settings (Static Analysis Results Interchange Format)
SARIF_VERSION = "2.1.0"
SARIF_INCLUDE_CODE_FLOWS = True

# ═══════════════════════════════════════════════════════════════════════════════
#  Remediation Guidance Configuration
# ═══════════════════════════════════════════════════════════════════════════════

# Use LLM for remediation
REMEDIATION_USE_LLM = True
REMEDIATION_MAX_LENGTH = 2000

# Include code examples in remediation
REMEDIATION_INCLUDE_CODE = True
REMEDIATION_CODE_LANGUAGES = ["python", "javascript", "java", "php", "csharp"]

# ═══════════════════════════════════════════════════════════════════════════════
#  Executive Summary Configuration
# ═══════════════════════════════════════════════════════════════════════════════

EXECUTIVE_SUMMARY_MAX_LENGTH = 500
INCLUDE_RISK_HEATMAP = True
INCLUDE_TREND_ANALYSIS = True
