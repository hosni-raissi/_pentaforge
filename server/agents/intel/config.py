

FORMATTER_ROUNDS = 3
FORMATTER_CALL_TIMEOUT_SECONDS = 300
FORMATTER_MAX_TOOLS_PER_ROUND: int = 2

# ── Update pipeline ───────────────────────────────────────────────────

RAG_REFRESH_DAYS: int = 3
UPDATE_DAYS_BACK: int = 14
UPDATE_MAX_RESULTS: int = 25

# ── Intel source registry (editable) ─────────────────────────────────
# Update these lists whenever you want to change which sources
# the Intel update pipeline verifies per target_type.
VERIFY_SOURCES: dict[str, list[str]] = {
    "web_app": ["OWASP-WSTG", "PayloadsAllTheThings", "HackTricks", "MITRE-ATTACK-Enterprise"],
    "api": ["OWASP-APISecurity", "PayloadsAllTheThings", "HackTricks", "MITRE-ATTACK-Enterprise"],
    "mobile": ["OWASP-MASTG", "HackTricks", "MITRE-ATTACK-Enterprise"],
    "infra": ["InternalAllTheThings", "HackingTheCloud", "MITRE-ATTACK-Enterprise", "PayloadsAllTheThings", "HackTricks"],
    "network": ["MITRE-ATTACK-Enterprise", "PayloadsAllTheThings", "HackTricks"],
    "iot": ["OWASP-FSTM", "HackTricks", "PayloadsAllTheThings"],
    "linux_server": ["InternalAllTheThings", "PayloadsAllTheThings", "HackTricks"],
    "desktop": ["PayloadsAllTheThings", "MITRE-ATTACK-Enterprise", "HackTricks"],
    "cloud": ["HackingTheCloud", "MITRE-ATTACK-Enterprise", "PayloadsAllTheThings"],
    "container": ["OWASP-K8sTop10", "HackingTheCloud", "MITRE-ATTACK-Enterprise"],
    "database": ["DatabaseSecurityAudit", "OWASP-ASVS", "PayloadsAllTheThings", "HackTricks"],
    "repository": ["OWASP-CICDTop10", "OSSFScorecard", "PayloadsAllTheThings"],
    "shared": ["PayloadsAllTheThings", "HackTricks", "CISA-KEV", "Vulhub", "MITRE-ATTACK-Enterprise"],
}

DEFAULT_VERIFY_SOURCES: list[str] = [
    "PayloadsAllTheThings",
    "HackTricks",
    "MITRE-ATTACK-Enterprise",
]

# ── Operational constants ──────────────────────────────────────────────

FORMATTER_ALLOWED_TOOLS: frozenset[str] = frozenset(
    {"search_rag"}
)
FORMATTER_TOOL_MAX_RETRIES: int = 2
MAX_SOURCE_ERRORS: int = 10
MAX_VERIFIED_COMPACT: int = 10
MAX_WEB_COMPACT: int = 6
COMPACT_HITS_LIMIT: int = 10
COMPACT_SNIPPET_LENGTH: int = 250
TOOL_OUTPUT_MAX_LENGTH: int = 4000
