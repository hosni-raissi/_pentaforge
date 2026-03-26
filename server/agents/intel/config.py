

FORMATTER_ROUNDS = 3
FORMATTER_CALL_TIMEOUT_SECONDS = 300

# ── Update pipeline ───────────────────────────────────────────────────

RAG_REFRESH_DAYS: int = 3
UPDATE_DAYS_BACK: int = 14
UPDATE_MAX_RESULTS: int = 25

# ── Intel source registry (editable) ─────────────────────────────────
# Update these lists whenever you want to change which sources
# the Intel update pipeline verifies per target_type.
VERIFY_SOURCES: dict[str, list[str]] = {
    "web": ["OWASP-WSTG", "PayloadsAllTheThings", "HackTricks", "MITRE-ATTACK"],
    "api": ["OWASP-APISecurity", "PayloadsAllTheThings", "HackTricks", "MITRE-ATTACK"],
    "network": ["MITRE-ATTACK", "PayloadsAllTheThings", "HackTricks"],
    "cloud": ["HackTricks", "MITRE-ATTACK", "PayloadsAllTheThings"],
    "mobile": ["OWASP-MASTG", "HackTricks", "MITRE-ATTACK"],
    "iot": ["OWASP-FSTM", "HackTricks", "PayloadsAllTheThings"],
    "binary": ["PayloadsAllTheThings", "HackTricks", "MITRE-ATTACK"],
    "identity": ["HackTricks", "MITRE-ATTACK", "PayloadsAllTheThings"],
    "supply_chain": ["MITRE-ATTACK", "PayloadsAllTheThings", "HackTricks"],
    "web3": ["PayloadsAllTheThings", "HackTricks"],
}

DEFAULT_VERIFY_SOURCES: list[str] = [
    "PayloadsAllTheThings",
    "HackTricks",
    "MITRE-ATTACK",
]

# ── Operational constants ──────────────────────────────────────────────

FORMATTER_ALLOWED_TOOLS: frozenset[str] = frozenset({"search_rag"})
FORMATTER_TOOL_MAX_RETRIES: int = 2
MAX_SOURCE_ERRORS: int = 10
MAX_VERIFIED_COMPACT: int = 10
MAX_WEB_COMPACT: int = 6
COMPACT_HITS_LIMIT: int = 10
COMPACT_SNIPPET_LENGTH: int = 250
TOOL_OUTPUT_MAX_LENGTH: int = 4000
