import subprocess
import re
import time
from typing import Optional, List
from pydantic import BaseModel, Field, validator


# ═══════════════════════════════════════════════════════
# 1. SCHEMAS
# ═══════════════════════════════════════════════════════

class TrafficInterceptRequest(BaseModel):

    interface: str = "any"
    duration: int = Field(default=60, ge=10, le=3600)
    tools: List[str] = ["tshark"]
    proxy_port: int = 8080

    @validator("tools")
    def validate_tools(cls, v):

        allowed = {
            "tshark",
            "tcpdump",
            "mitmproxy"
        }

        for t in v:
            if t not in allowed:
                raise ValueError(f"Tool not allowed: {t}")

        return v


class TrafficFinding(BaseModel):
    type: str
    value: str


class TrafficResult(BaseModel):
    success: bool
    findings: List[TrafficFinding] = []
    hosts: List[str] = []
    urls: List[str] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float


# ═══════════════════════════════════════════════════════
# 2. SAFE EXECUTION
# ═══════════════════════════════════════════════════════

def safe_execute(cmd, timeout):

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )

        return result.stdout, result.stderr, result.returncode

    except subprocess.TimeoutExpired:
        return "", "Timeout", -1

    except Exception as e:
        return "", str(e), -1


# ═══════════════════════════════════════════════════════
# 3. TRAFFIC ANALYSIS
# ═══════════════════════════════════════════════════════

def analyze_traffic(output):

    findings = []
    hosts = set()
    urls = set()

    api_pattern = r"(api[_-]?key|token|authorization)\s*[:=]\s*([A-Za-z0-9\-_\.]+)"
    url_pattern = r"https?://[^\s\"']+"
    auth_pattern = r"Authorization:\s*(.+)"

    for line in output.splitlines():

        # URLs
        url_match = re.search(url_pattern, line)
        if url_match:
            urls.add(url_match.group(0))

        # Hosts
        host_match = re.search(r"Host:\s*(\S+)", line)
        if host_match:
            hosts.add(host_match.group(1))

        # API Keys
        api_match = re.search(api_pattern, line, re.IGNORECASE)
        if api_match:
            findings.append(
                TrafficFinding(
                    type="api_key_leak",
                    value=line.strip()
                )
            )

        # Authorization headers
        auth_match = re.search(auth_pattern, line)
        if auth_match:
            findings.append(
                TrafficFinding(
                    type="authorization_header",
                    value=line.strip()
                )
            )

        # Cleartext HTTP
        if "http://" in line.lower():
            findings.append(
                TrafficFinding(
                    type="cleartext_http",
                    value=line.strip()
                )
            )

    return list(hosts), list(urls), findings


# ═══════════════════════════════════════════════════════
# 4. MAIN TOOL
# ═══════════════════════════════════════════════════════

def desktop_traffic_intercept(
    interface="any",
    duration=60,
    tools=["tshark"],
    proxy_port=8080
):

    start = time.time()

    findings = []
    hosts = []
    urls = []
    raw = ""

    # ─────────────────────────
    # TSHARK CAPTURE
    # ─────────────────────────

    if "tshark" in tools:

        cmd = [
            "tshark",
            "-i", interface,
            "-a", f"duration:{duration}",
            "-Y", "http",
            "-T", "fields",
            "-e", "http.host",
            "-e", "http.request.full_uri",
            "-e", "http.authorization"
        ]

        stdout, stderr, rc = safe_execute(cmd, duration + 10)

        raw += stdout

        h, u, f = analyze_traffic(stdout)

        hosts.extend(h)
        urls.extend(u)
        findings.extend(f)

    # ─────────────────────────
    # TCPDUMP
    # ─────────────────────────

    if "tcpdump" in tools:

        cmd = [
            "tcpdump",
            "-i", interface,
            "-A",
            "-c", "200"
        ]

        stdout, stderr, rc = safe_execute(cmd, duration)

        raw += stdout

        h, u, f = analyze_traffic(stdout)

        hosts.extend(h)
        urls.extend(u)
        findings.extend(f)

    # ─────────────────────────
    # MITMPROXY
    # ─────────────────────────

    if "mitmproxy" in tools:

        cmd = [
            "mitmdump",
            "-p", str(proxy_port),
            "--set", "block_global=false"
        ]

        stdout, stderr, rc = safe_execute(cmd, duration)

        raw += stdout

    return TrafficResult(
        success=True,
        findings=findings,
        hosts=list(set(hosts)),
        urls=list(set(urls)),
        raw_output=raw[:5000],
        execution_time=round(time.time() - start, 2)
    ).model_dump()


# ═══════════════════════════════════════════════════════
# 5. TOOL DEFINITION
# ═══════════════════════════════════════════════════════

DESKTOP_TRAFFIC_INTERCEPT_TOOL = {

    "name": "desktop_traffic_intercept",

    "description": (
        "Intercept desktop application network traffic using tshark, tcpdump, "
        "and mitmproxy. Detect API keys, authorization headers, cleartext HTTP, "
        "and suspicious endpoints."
    ),

    "parameters": {

        "type": "object",

        "properties": {

            "interface": {
                "type": "string",
                "description": "Network interface (eth0, wlan0, any)"
            },

            "duration": {
                "type": "integer",
                "description": "Capture duration in seconds"
            },

            "tools": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tools to use: tshark, tcpdump, mitmproxy"
            },

            "proxy_port": {
                "type": "integer",
                "description": "MITM proxy port"
            }

        }

    }

}