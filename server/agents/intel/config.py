

FORMATTER_ROUNDS = 3
FORMATTER_CALL_TIMEOUT_SECONDS = 300

# ── Update pipeline ───────────────────────────────────────────────────

RAG_REFRESH_DAYS: int = 3
UPDATE_DAYS_BACK: int = 14
UPDATE_MAX_RESULTS: int = 25

# ── Operational constants ──────────────────────────────────────────────

FORMATTER_ALLOWED_TOOLS: frozenset[str] = frozenset({"search_rag", "search_web"})
FORMATTER_TOOL_MAX_RETRIES: int = 2
MAX_SOURCE_ERRORS: int = 10
MAX_VERIFIED_COMPACT: int = 10
MAX_WEB_COMPACT: int = 6
COMPACT_HITS_LIMIT: int = 10
COMPACT_SNIPPET_LENGTH: int = 250
TOOL_OUTPUT_MAX_LENGTH: int = 4000
