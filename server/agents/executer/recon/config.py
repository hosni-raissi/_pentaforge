"""Configuration for the Recon executer agent."""

import os
import socket

# ═══════════════════════════════════════════════════════════════════════════════
#  LLM Configuration
# ═══════════════════════════════════════════════════════════════════════════════

MAX_TOOL_ROUNDS = 3
LLM_CALL_TIMEOUT_SECONDS = 300
RECON_CONTEXT_WINDOW_MAX_TOKENS = 15000
RECON_CONTEXT_WINDOW_SEND_THRESHOLD_TOKENS = 15000
RECON_MAX_TOOL_CALLS_PER_ROUND = 2
WARMUP_RECON_MAX_TOOL_CALLS_PER_ROUND = 3
RECON_TOOL_EXECUTION_TIMEOUT_SECONDS = 240

# ═══════════════════════════════════════════════════════════════════════════════
#  Port Scanning Configuration
# ═══════════════════════════════════════════════════════════════════════════════

NMAP_DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443"
NMAP_FULL_PORTS = "1-65535"
NMAP_TOP_PORTS = 1000
NMAP_SCAN_TIMEOUT = 240  # 4 minutes max per tool execution
MASSCAN_RATE = 1000  # packets per second

# ═══════════════════════════════════════════════════════════════════════════════
#  Subdomain Enumeration Configuration
# ═══════════════════════════════════════════════════════════════════════════════

AMASS_TIMEOUT = 240  # 4 minutes max per tool
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

TRUFFLEHOG_TIMEOUT = 240  # 4 minutes max
GITLEAKS_TIMEOUT = 240  # 4 minutes max
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

# Optional Burp launcher overrides for web tooling.
# Set these directly in recon config (no .env dependency).
BURP_SUITE_CMD = "burpsuite"
BURP_SUITE_JAR = ""

# Global auto-capture via Burp proxy (applies to HTTP clients that honor env vars).
BURP_AUTO_CAPTURE = True
BURP_PROXY_HOST = "127.0.0.1"
BURP_PROXY_PORT = 8080
BURP_PROXY_URL = f"http://{BURP_PROXY_HOST}:{BURP_PROXY_PORT}"
BURP_CAPTURE_CLEAR_NO_PROXY = True


def _port_accepting_connections(host: str, port: int, timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _enable_burp_auto_capture() -> bool:
    if not BURP_AUTO_CAPTURE:
        return False

    if not _port_accepting_connections(BURP_PROXY_HOST, BURP_PROXY_PORT):
        return False

    os.environ["HTTP_PROXY"] = BURP_PROXY_URL
    os.environ["HTTPS_PROXY"] = BURP_PROXY_URL
    os.environ["http_proxy"] = BURP_PROXY_URL
    os.environ["https_proxy"] = BURP_PROXY_URL

    if BURP_CAPTURE_CLEAR_NO_PROXY:
        os.environ["NO_PROXY"] = ""
        os.environ["no_proxy"] = ""

    return True


BURP_AUTO_CAPTURE_ACTIVE = _enable_burp_auto_capture()

# ═══════════════════════════════════════════════════════════════════════════════
#  Security Configuration — Target Blocking
# ═══════════════════════════════════════════════════════════════════════════════

from urllib.parse import urlparse as _urlparse

# Centralized blocked-hosts set.  ALL recon tools import `is_blocked_host`
# from this module instead of maintaining their own hardcoded lists.
# Leave empty to allow every target (including localhost); populate as needed.
BLOCKED_HOSTS: set[str] = set()
# Example:  BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal"}

# Backward-compatible aliases — network/server tools still import these.
# Kept empty so nothing is blocked; migrate callers to is_blocked_host() over time.
BLOCKED_HOSTNAMES: set[str] = set()
BLOCKED_NETWORKS: list = []


def is_blocked_host(value: str) -> bool:
    """Return True when *value* (hostname, IP, or full URL) is blocked."""
    if not BLOCKED_HOSTS:
        return False
    host = value.strip().lower()
    # If it looks like a URL, extract the hostname.
    if host.startswith(("http://", "https://")):
        parsed = _urlparse(host)
        host = (parsed.hostname or "").lower()
    # Strip port if present (e.g. "127.0.0.1:3001").
    host = host.split(":")[0]
    return host in BLOCKED_HOSTS
