"""Configuration for the Recon executer agent."""

import os
import socket

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
#  Security Configuration
# ═══════════════════════════════════════════════════════════════════════════════

import ipaddress

# List of ipaddress.IPv4Network or IPv6Network objects to block (e.g. 10.0.0.0/8)
BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fe80::/10"),
]

BLOCKED_HOSTNAMES: list[str] = [
    "localhost", "broadcasthost", "local"
]

