"""Configuration for the Retest executer agent."""

# ═══════════════════════════════════════════════════════════════════════════════
#  LLM Configuration
# ═══════════════════════════════════════════════════════════════════════════════

MAX_TOOL_ROUNDS = 10
LLM_CALL_TIMEOUT_SECONDS = 240

# ═══════════════════════════════════════════════════════════════════════════════
#  Payload Replay Configuration
# ═══════════════════════════════════════════════════════════════════════════════

# Maximum number of replay attempts per finding
MAX_REPLAY_ATTEMPTS = 5

# Delay between replay attempts (seconds)
REPLAY_DELAY_SECONDS = 1.0

# Timeout for replay requests
REPLAY_TIMEOUT_SECONDS = 30

# Retry with mutations on initial failure
AUTO_MUTATE_ON_FAILURE = True

# ═══════════════════════════════════════════════════════════════════════════════
#  Bypass Mutation Configuration
# ═══════════════════════════════════════════════════════════════════════════════

# Use LLM for generating bypass mutations
USE_LLM_MUTATIONS = True

# Maximum mutations to try per payload
MAX_MUTATIONS_PER_PAYLOAD = 10

# Mutation strategies
MUTATION_STRATEGIES = [
    "encoding_chain",    # URL encode, base64, unicode, hex
    "case_variation",    # Upper/lower/mixed case
    "whitespace",        # Add spaces, tabs, newlines
    "comment_injection", # SQL/HTML/JS comments
    "null_byte",         # Null byte injection
    "double_encoding",   # Double URL encoding
    "unicode_normalization",  # Unicode normalization bypass
    "chunked_encoding",  # HTTP chunked transfer
    "parameter_pollution", # HPP techniques
    "content_type_manipulation",  # Change content-type
]

# Encoding chains to try
ENCODING_CHAINS = [
    ["url"],
    ["base64"],
    ["url", "url"],  # Double URL encode
    ["unicode", "url"],
    ["hex", "url"],
    ["base64", "url"],
    ["url", "base64", "url"],
]

# ═══════════════════════════════════════════════════════════════════════════════
#  Patch Confidence Scoring (ML-based)
# ═══════════════════════════════════════════════════════════════════════════════

# Enable ML-based patch confidence scoring
ENABLE_ML_SCORING = True

# Minimum confidence to consider patch effective
PATCH_CONFIDENCE_THRESHOLD = 0.85

# Features considered in patch confidence
PATCH_CONFIDENCE_FEATURES = [
    "original_payload_blocked",      # Original payload now blocked
    "mutations_blocked",             # Mutation variants blocked
    "error_messages_sanitized",      # Error messages no longer leak info
    "response_timing_normalized",    # No timing oracle
    "consistent_error_handling",     # Same error for all mutations
    "http_status_appropriate",       # Proper HTTP status codes
    "content_type_secure",           # Secure content-type headers
    "no_data_leakage",              # No data in error responses
]

# Confidence score weights
FEATURE_WEIGHTS = {
    "original_payload_blocked": 0.25,
    "mutations_blocked": 0.20,
    "error_messages_sanitized": 0.15,
    "response_timing_normalized": 0.10,
    "consistent_error_handling": 0.10,
    "http_status_appropriate": 0.08,
    "content_type_secure": 0.07,
    "no_data_leakage": 0.05,
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Retest Verdicts
# ═══════════════════════════════════════════════════════════════════════════════

RETEST_VERDICTS = {
    "fixed": "Vulnerability has been fully remediated",
    "partial": "Partial remediation; some bypass variants still work",
    "not_fixed": "Vulnerability still exploitable with original payload",
    "bypassed": "Original fixed, but bypass mutations successful",
    "regression": "Previously fixed vulnerability has regressed",
    "inconclusive": "Unable to determine fix status; needs manual review",
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Evidence Collection
# ═══════════════════════════════════════════════════════════════════════════════

# Store retest evidence
STORE_RETEST_EVIDENCE = True

# Evidence output path
EVIDENCE_OUTPUT_PATH = "/tmp/pentaforge/retest_evidence"

# Include diff between original and retest
INCLUDE_RESPONSE_DIFF = True

# ═══════════════════════════════════════════════════════════════════════════════
#  Regression Detection
# ═══════════════════════════════════════════════════════════════════════════════

# Enable regression detection
ENABLE_REGRESSION_DETECTION = True

# Historical comparison depth
REGRESSION_HISTORY_DEPTH = 5

# Alert on regression
ALERT_ON_REGRESSION = True
