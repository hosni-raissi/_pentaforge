"""Intel node configuration for refresh scheduling and source selection."""

from __future__ import annotations

RAG_REFRESH_DAYS: int = 3
UPDATE_DAYS_BACK: int = 14
UPDATE_MAX_RESULTS: int = 25

VERIFY_SOURCES: dict[str, list[str]] = {
    "web_app": [
        "OWASP-WSTG",
        "PayloadsAllTheThings",
        "HackTricks",
        "MITRE-ATTACK-Enterprise",
    ],
    "api": [
        "OWASP-APISecurity",
        "PayloadsAllTheThings",
        "HackTricks",
        "MITRE-ATTACK-Enterprise",
    ],
    "mobile": [
        "OWASP-MASTG",
        "HackTricks",
        "MITRE-ATTACK-Enterprise",
    ],
    "infra": [
        "InternalAllTheThings",
        "HackingTheCloud",
        "MITRE-ATTACK-Enterprise",
        "PayloadsAllTheThings",
        "HackTricks",
    ],
    "network": [
        "MITRE-ATTACK-Enterprise",
        "PayloadsAllTheThings",
        "HackTricks",
    ],
    "iot": [
        "OWASP-FSTM",
        "HackTricks",
        "PayloadsAllTheThings",
    ],
    "linux_server": [
        "InternalAllTheThings",
        "PayloadsAllTheThings",
        "HackTricks",
    ],
    "desktop": [
        "PayloadsAllTheThings",
        "MITRE-ATTACK-Enterprise",
        "HackTricks",
    ],
    "cloud": [
        "HackingTheCloud",
        "MITRE-ATTACK-Enterprise",
        "PayloadsAllTheThings",
    ],
    "container": [
        "OWASP-K8sTop10",
        "HackingTheCloud",
        "MITRE-ATTACK-Enterprise",
    ],
    "repository": [
        "OWASP-CICDTop10",
        "OSSFScorecard",
        "PayloadsAllTheThings",
    ],
    "shared": [
        "PayloadsAllTheThings",
        "HackTricks",
        "CISA-KEV",
        "Vulhub",
        "MITRE-ATTACK-Enterprise",
        "DatabaseSecurityAudit",
    ],
}

DEFAULT_VERIFY_SOURCES: list[str] = [
    "PayloadsAllTheThings",
    "HackTricks",
    "MITRE-ATTACK-Enterprise",
]
