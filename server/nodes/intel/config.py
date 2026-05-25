"""Intel node configuration for refresh scheduling and source selection."""

from __future__ import annotations

RAG_REFRESH_DAYS: int = 5
UPDATE_DAYS_BACK: int = 14
UPDATE_MAX_RESULTS: int = 25
INTEL_INLINE_MAX_SOURCES: int = 2
INTEL_INLINE_MAX_DOCS_PER_SOURCE: int = 60
INTEL_INLINE_SOURCE_TIMEOUT_SECONDS: int = 300

VERIFY_SOURCES: dict[str, list[str]] = {
    "web_app": [
        "OWASP-WSTG",
        "PortSwigger-WebSecurity",
    ],
    "api": [
        "OWASP-APISecurity",
        "PortSwigger-WebSecurity",
    ],
    "mobile": [
        "OWASP-MASTG",
        "HackTricks-Android",
    ],
    "infra": [
        "InternalAllTheThings",
        "CISA-KEV",
    ],
    "network": [
        "MitreAttack-Discovery",
        "MitreAttack-LateralMovement",
    ],
    "iot": [
        "OWASP-FSTM",
        "CISA-KEV",
    ],
    "linux_server": [
        "InternalAllTheThings",
        "GTFOBins",
    ],
    "desktop": [
        "LOLBAS",
        "CISA-KEV",
    ],
    "cloud": [
        "HackingTheCloud",
        "CISA-KEV",
    ],
    "container": [
        "OWASP-K8sTop10",
        "CISA-KEV",
    ],
    "repository": [
        "OWASP-CICDTop10",
        "OSSFScorecard",
    ],
    "shared": [
        "CISA-KEV",
        "Vulhub",
    ],
}

DEFAULT_VERIFY_SOURCES: list[str] = [
    "CISA-KEV",
    "OWASP-WSTG",
]
