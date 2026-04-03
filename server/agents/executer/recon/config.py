"""Configuration for the Recon executer agent."""

# ═══════════════════════════════════════════════════════════════════════════════
#  LLM Configuration
# ═══════════════════════════════════════════════════════════════════════════════

MAX_TOOL_ROUNDS = 10
LLM_CALL_TIMEOUT_SECONDS = 300

# ═══════════════════════════════════════════════════════════════════════════════
#  Port Scanning Configuration
# ═══════════════════════════════════════════════════════════════════════════════

NMAP_DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443"
NMAP_FULL_PORTS = "1-65535"
NMAP_TOP_PORTS = 1000
NMAP_SCAN_TIMEOUT = 600  # 10 minutes
MASSCAN_RATE = 1000  # packets per second

# ═══════════════════════════════════════════════════════════════════════════════
#  Subdomain Enumeration Configuration
# ═══════════════════════════════════════════════════════════════════════════════

AMASS_TIMEOUT = 300  # 5 minutes
SUBDOMAIN_WORDLIST_SIZE = 10000  # top subdomains to check
MAX_SUBDOMAINS_RETURN = 500

# ═══════════════════════════════════════════════════════════════════════════════
#  OSINT Configuration
# ═══════════════════════════════════════════════════════════════════════════════

OSINT_MAX_RESULTS = 100
GITHUB_SEARCH_LIMIT = 50
SHODAN_LIMIT = 100

# ═══════════════════════════════════════════════════════════════════════════════
#  Secret Discovery Configuration
# ═══════════════════════════════════════════════════════════════════════════════

TRUFFLEHOG_TIMEOUT = 300
GITLEAKS_TIMEOUT = 300
MAX_SECRETS_RETURN = 100

# ═══════════════════════════════════════════════════════════════════════════════
#  Stealth Analyzer Configuration
# ═══════════════════════════════════════════════════════════════════════════════

STEALTH_MODE_ENABLED = True
HONEYPOT_DETECTION_ENABLED = True
TARPIT_DETECTION_ENABLED = True

# Scan cadence thresholds
STEALTH_MIN_DELAY_MS = 100
STEALTH_MAX_DELAY_MS = 5000
STEALTH_ADAPTIVE_FACTOR = 1.5  # Increase delay by this factor on suspicious response

# Detection patterns
HONEYPOT_INDICATORS = [
    "all_ports_open",           # Too many ports open
    "identical_banners",        # Same banner on multiple ports
    "fake_services",            # Services that respond incorrectly
    "response_time_uniform",    # Uniform response times (unusual)
]

TARPIT_INDICATORS = [
    "slow_response",            # Unusually slow response
    "incomplete_handshake",     # TCP handshake doesn't complete
    "connection_hang",          # Connection hangs indefinitely
]

# ═══════════════════════════════════════════════════════════════════════════════
#  Technology Detection Configuration
# ═══════════════════════════════════════════════════════════════════════════════

WAPPALYZER_TIMEOUT = 60
WHATWEB_TIMEOUT = 60
TECH_DETECTION_MAX_URLS = 50

# ═══════════════════════════════════════════════════════════════════════════════
#  Tool Paths (configurable per environment)
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_PATHS = {
    "nmap": "nmap",
    "masscan": "masscan",
    "amass": "amass",
    "subfinder": "subfinder",
    "trufflehog": "trufflehog",
    "gitleaks": "gitleaks",
    "whatweb": "whatweb",
    "httpx": "httpx",
    "nuclei": "nuclei",
}
