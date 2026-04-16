"""Configuration for the Verify executer agent."""

# ═══════════════════════════════════════════════════════════════════════════════
#  LLM Configuration
# ═══════════════════════════════════════════════════════════════════════════════

MAX_TOOL_ROUNDS = 4
LLM_CALL_TIMEOUT_SECONDS = 300
VERIFY_CONTEXT_WINDOW_MAX_TOKENS = 15000
VERIFY_CONTEXT_WINDOW_SEND_THRESHOLD_TOKENS = 15000
VERIFY_MAX_TOOL_CALLS_PER_ROUND = 2

# ═══════════════════════════════════════════════════════════════════════════════
#  Screenshot Configuration (Playwright)
# ═══════════════════════════════════════════════════════════════════════════════

SCREENSHOT_TIMEOUT = 30000  # 30 seconds
SCREENSHOT_VIEWPORT_WIDTH = 1920
SCREENSHOT_VIEWPORT_HEIGHT = 1080
SCREENSHOT_QUALITY = 90  # JPEG quality for compression
SCREENSHOT_FORMAT = "png"  # png or jpeg

# Where to store screenshots
SCREENSHOT_STORAGE_PATH = "/tmp/pentaforge/screenshots"

# Redaction settings - NEVER capture payloads in screenshots
REDACT_URL_PARAMS = True
REDACT_FORM_DATA = True
REDACT_COOKIES = True

# ═══════════════════════════════════════════════════════════════════════════════
#  Vision Model Configuration
# ═══════════════════════════════════════════════════════════════════════════════

VISION_MODEL = "llava:13b"  # Or gpt-4-vision-preview for cloud
VISION_TIMEOUT = 60
VISION_MAX_TOKENS = 2000

# Confidence thresholds for validation
VISION_CONFIDENCE_THRESHOLD = 0.7  # Minimum confidence for positive finding
FALSE_POSITIVE_THRESHOLD = 0.8  # Above this = likely false positive

# ═══════════════════════════════════════════════════════════════════════════════
#  Evidence Chain Configuration
# ═══════════════════════════════════════════════════════════════════════════════

EVIDENCE_HASH_ALGORITHM = "sha256"
EVIDENCE_STORAGE_PATH = "/tmp/pentaforge/evidence"

# Signed evidence chain
SIGN_EVIDENCE = True
EVIDENCE_SIGNING_KEY = ""  # Set via environment

# Evidence retention
EVIDENCE_RETENTION_DAYS = 90

# ═══════════════════════════════════════════════════════════════════════════════
#  Bounding Box Annotation Configuration
# ═══════════════════════════════════════════════════════════════════════════════

ANNOTATION_COLOR = "#FF0000"  # Red
ANNOTATION_BORDER_WIDTH = 3
ANNOTATION_FONT_SIZE = 14
ANNOTATION_LABEL_BG_COLOR = "#FF0000"
ANNOTATION_LABEL_TEXT_COLOR = "#FFFFFF"

# ═══════════════════════════════════════════════════════════════════════════════
#  False Positive Detection
# ═══════════════════════════════════════════════════════════════════════════════

# Known false positive patterns
FALSE_POSITIVE_PATTERNS = [
    "reflected_but_encoded",      # XSS reflected but properly encoded
    "sqli_syntax_but_no_dump",    # SQL error but no data extraction
    "timeout_but_consistent",     # Time-based but consistent response times
    "custom_error_page",          # Custom error pages that look like vulns
]

# Verification retry settings
VERIFICATION_MAX_RETRIES = 3
VERIFICATION_RETRY_DELAY = 2  # seconds

# ═══════════════════════════════════════════════════════════════════════════════
#  Browser Configuration
# ═══════════════════════════════════════════════════════════════════════════════

BROWSER_TYPE = "chromium"  # chromium, firefox, webkit
BROWSER_HEADLESS = True
BROWSER_IGNORE_HTTPS_ERRORS = True
BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 PentaForge/1.0"

# Request interception
INTERCEPT_REQUESTS = True
BLOCK_TRACKING = True
BLOCK_ADS = True
