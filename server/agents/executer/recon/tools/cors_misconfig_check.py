import subprocess
import json
import re
import time
import requests
import concurrent.futures
from typing import Optional, Any
from pydantic import BaseModel, Field, validator

# ══════════════════════════════════════════════════════════════
# 1. SCHEMAS
# ══════════════════════════════════════════════════════════════

class CORSCheckRequest(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    timeout: int = Field(default=600, ge=30, le=7200)
    endpoints: list[str] = []          # optional pre-supplied endpoint list
    origins: list[str] = []            # custom origins to test

    @validator("tool")
    def validate_tool(cls, v):
        allowed = {"corscanner", "curl", "manual"}
        if v not in allowed:
            raise ValueError(f"Tool '{v}' not allowed. Use: {allowed}")
        return v

    @validator("target")
    def validate_target(cls, v):
        blocked = ["127.0.0.1", "localhost", "0.0.0.0", "::1"]
        if v.strip() in blocked:
            raise ValueError(f"Target '{v}' is blocked")

        domain_pattern = r"^https?://[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}"
        bare_domain    = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$"
        ip_pattern     = r"^https?://(\d{1,3}\.){3}\d{1,3}"

        if not (re.match(domain_pattern, v) or
                re.match(bare_domain, v)    or
                re.match(ip_pattern, v)):
            raise ValueError(f"Invalid target: {v}")
        return v.strip()

    @validator("args")
    def validate_args(cls, v):
        dangerous_chars = [";", "&&", "||", "|", "`", "$(", ">>", "'", '"']
        blocked_flags   = ["-o", "--output", "-O"]

        for arg in v:
            for char in dangerous_chars:
                if char in arg:
                    raise ValueError(f"Dangerous character '{char}' in arg: {arg}")
            for flag in blocked_flags:
                if arg.strip() == flag:
                    raise ValueError(f"Blocked flag: {flag}")
        return v


# ── Single CORS test result ──
class CORSTestResult(BaseModel):
    origin_sent: str                            # what we sent as Origin:
    acao_header: Optional[str] = None           # Access-Control-Allow-Origin returned
    acac_header: Optional[str] = None           # Access-Control-Allow-Credentials
    acam_header: Optional[str] = None           # Access-Control-Allow-Methods
    acah_header: Optional[str] = None           # Access-Control-Allow-Headers
    acae_header: Optional[str] = None           # Access-Control-Expose-Headers
    acma_header: Optional[str] = None           # Access-Control-Max-Age
    http_status: Optional[int] = None
    varies_origin: bool = False                 # Vary: Origin present
    vulnerable: bool = False
    finding: str = "none"                       # finding type key
    evidence: list[str] = []


# ── Per-endpoint result ──
class EndpointResult(BaseModel):
    url: str
    method: str = "GET"
    tests: list[CORSTestResult] = []
    vulnerable: bool = False
    severity: str = "info"             # info / low / medium / high / critical
    findings: list[str] = []          # deduplicated finding keys
    remediation: list[str] = []


# ── Final result ──
class CORSScanResult(BaseModel):
    success: bool
    tool: str
    target: str
    command: str
    total_endpoints: int = 0
    total_vulnerable: int = 0
    endpoints: list[EndpointResult] = []
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


# ══════════════════════════════════════════════════════════════
# 2. CORS FINDING DEFINITIONS
# ══════════════════════════════════════════════════════════════

FINDINGS: dict[str, dict] = {

    # ── Critical ──────────────────────────────────────────────
    "wildcard_with_credentials": {
        "severity":    "critical",
        "title":       "Wildcard Origin with Credentials Allowed",
        "description": (
            "ACAO: * combined with ACAC: true. "
            "Although browsers block this combination per spec, "
            "some custom clients / misconfigured servers still expose data."
        ),
        "remediation": [
            "Never combine Access-Control-Allow-Origin: * with "
            "Access-Control-Allow-Credentials: true",
            "Use an explicit allowlist of trusted origins instead of wildcard",
        ],
    },
    "origin_reflected_with_credentials": {
        "severity":    "critical",
        "title":       "Arbitrary Origin Reflected + Credentials",
        "description": (
            "Server echoes back any Origin header AND sets "
            "Access-Control-Allow-Credentials: true. "
            "Any website can read authenticated responses."
        ),
        "remediation": [
            "Validate Origin against a strict allowlist before reflecting",
            "Never reflect arbitrary origins with credentials enabled",
            "Implement server-side origin validation logic",
        ],
    },
    "null_origin_with_credentials": {
        "severity":    "critical",
        "title":       "Null Origin Accepted with Credentials",
        "description": (
            "Server accepts Origin: null with credentials. "
            "Attackers can exploit sandboxed iframes or "
            "local HTML files to make credentialed cross-origin requests."
        ),
        "remediation": [
            "Never whitelist the null origin in production",
            "Reject requests with Origin: null",
        ],
    },

    # ── High ──────────────────────────────────────────────────
    "origin_reflected_no_credentials": {
        "severity":    "high",
        "title":       "Arbitrary Origin Reflected (No Credentials)",
        "description": (
            "Server reflects any Origin without credentials. "
            "Unauthenticated responses are readable cross-origin."
        ),
        "remediation": [
            "Validate Origin against a strict allowlist",
            "Return ACAO only for explicitly trusted origins",
        ],
    },
    "pre_domain_bypass": {
        "severity":    "high",
        "title":       "Pre-Domain Bypass (Suffix Match)",
        "description": (
            "Origin validation only checks that the request origin ENDS WITH "
            "the trusted domain. e.g. evil-example.com accepted when "
            "example.com is trusted."
        ),
        "remediation": [
            "Use exact-match or regex anchored validation (^https://example\\.com$)",
            "Do not use endsWith() / suffix matching for origin validation",
        ],
    },
    "post_domain_bypass": {
        "severity":    "high",
        "title":       "Post-Domain Bypass (Prefix Match)",
        "description": (
            "Origin validation only checks that the request origin STARTS WITH "
            "the trusted domain. e.g. example.com.evil.com accepted."
        ),
        "remediation": [
            "Anchor regex to end of string: ^https://example\\.com$",
            "Do not use startsWith() for origin validation",
        ],
    },
    "subdomain_bypass": {
        "severity":    "high",
        "title":       "Wildcard Subdomain Accepted",
        "description": (
            "Server accepts any subdomain of the trusted domain. "
            "An XSS on any subdomain leads to full CORS bypass."
        ),
        "remediation": [
            "Enumerate and explicitly allow only required subdomains",
            "Avoid wildcard subdomain matching (*.example.com)",
        ],
    },
    "http_origin_trusted_on_https": {
        "severity":    "high",
        "title":       "HTTP Origin Trusted on HTTPS Endpoint",
        "description": (
            "Secure HTTPS endpoint accepts an HTTP (insecure) origin. "
            "Allows protocol downgrade / MITM CORS bypass."
        ),
        "remediation": [
            "Only trust HTTPS origins for HTTPS endpoints",
            "Reject http:// origins on secure endpoints",
        ],
    },

    # ── Medium ────────────────────────────────────────────────
    "wildcard_origin_no_credentials": {
        "severity":    "medium",
        "title":       "Wildcard Origin (No Credentials)",
        "description": (
            "ACAO: * without credentials. "
            "Unauthenticated / public data exposed to all origins. "
            "Acceptable for truly public APIs, otherwise a finding."
        ),
        "remediation": [
            "Assess whether this endpoint really needs to be public",
            "If not, restrict to specific allowed origins",
        ],
    },
    "null_origin_no_credentials": {
        "severity":    "medium",
        "title":       "Null Origin Accepted (No Credentials)",
        "description": (
            "Server accepts Origin: null without credentials. "
            "Can be exploited from sandboxed contexts."
        ),
        "remediation": [
            "Remove null from origin allowlist",
            "Reject null origin unless required for specific use case",
        ],
    },
    "vary_origin_missing": {
        "severity":    "medium",
        "title":       "Vary: Origin Header Missing",
        "description": (
            "Server sends CORS headers but omits Vary: Origin. "
            "CDN / proxy may cache CORS responses and serve wrong "
            "ACAO to different origins."
        ),
        "remediation": [
            "Always include Vary: Origin when returning dynamic ACAO headers",
        ],
    },

    # ── Low ───────────────────────────────────────────────────
    "exposed_sensitive_headers": {
        "severity":    "low",
        "title":       "Sensitive Headers Exposed via Access-Control-Expose-Headers",
        "description": (
            "Authorization / Cookie / X-Auth-Token exposed cross-origin."
        ),
        "remediation": [
            "Only expose headers that are required by cross-origin clients",
            "Never expose Authorization or Set-Cookie via ACAE",
        ],
    },
    "overly_permissive_methods": {
        "severity":    "low",
        "title":       "Overly Permissive Access-Control-Allow-Methods",
        "description": "PUT / DELETE / PATCH allowed cross-origin without restriction.",
        "remediation": [
            "Restrict allowed methods to the minimum required",
            "Remove unsafe methods (PUT, DELETE, PATCH) unless explicitly needed",
        ],
    },
    "preflight_wildcard_headers": {
        "severity":    "low",
        "title":       "Wildcard Access-Control-Allow-Headers",
        "description": "ACAH: * allows any custom header cross-origin.",
        "remediation": [
            "Enumerate only the specific headers your API requires",
        ],
    },
}


# ══════════════════════════════════════════════════════════════
# 3. TEST ORIGIN PAYLOADS
# ══════════════════════════════════════════════════════════════

def build_test_origins(target_url: str) -> list[dict[str, str]]:
    """
    Build the full set of CORS bypass origin payloads for a target.
    Each entry: {"origin": ..., "label": ..., "test_type": ...}
    """
    # Extract base domain from target
    m = re.search(r"https?://([^/:]+)", target_url)
    if not m:
        base_domain = target_url
    else:
        base_domain = m.group(1)

    # Strip port
    bare_domain = re.sub(r":\d+$", "", base_domain)

    # Split into parts for manipulation
    parts = bare_domain.split(".")
    tld   = ".".join(parts[-2:]) if len(parts) >= 2 else bare_domain

    origins = [
        # ── Wildcard / generic ──
        {
            "origin":     "null",
            "label":      "Null origin",
            "test_type":  "null_origin",
        },
        {
            "origin":     "*",
            "label":      "Wildcard star (invalid as request origin)",
            "test_type":  "wildcard_star",
        },

        # ── Reflected / arbitrary ──
        {
            "origin":     f"https://evil.com",
            "label":      "Arbitrary external origin",
            "test_type":  "arbitrary_origin",
        },
        {
            "origin":     f"https://attacker.io",
            "label":      "Attacker domain",
            "test_type":  "arbitrary_origin",
        },

        # ── Pre-domain bypass ──
        {
            "origin":     f"https://evil-{tld}",
            "label":      "Pre-domain (suffix match bypass)",
            "test_type":  "pre_domain_bypass",
        },
        {
            "origin":     f"https://evil.{tld}.attacker.com",
            "label":      "Domain in path (suffix confusion)",
            "test_type":  "pre_domain_bypass",
        },

        # ── Post-domain bypass ──
        {
            "origin":     f"https://{bare_domain}.evil.com",
            "label":      "Post-domain (prefix match bypass)",
            "test_type":  "post_domain_bypass",
        },
        {
            "origin":     f"https://{bare_domain}.attacker.io",
            "label":      "Post-domain variation",
            "test_type":  "post_domain_bypass",
        },

        # ── Subdomain bypass ──
        {
            "origin":     f"https://evil.{bare_domain}",
            "label":      "Arbitrary subdomain",
            "test_type":  "subdomain_bypass",
        },
        {
            "origin":     f"https://xss.{bare_domain}",
            "label":      "XSS subdomain simulation",
            "test_type":  "subdomain_bypass",
        },
        {
            "origin":     f"https://pwned.{bare_domain}",
            "label":      "Attacker subdomain",
            "test_type":  "subdomain_bypass",
        },

        # ── HTTP origin on HTTPS ──
        {
            "origin":     f"http://{bare_domain}",
            "label":      "HTTP origin on HTTPS endpoint",
            "test_type":  "http_origin",
        },
        {
            "origin":     f"http://evil.{bare_domain}",
            "label":      "HTTP subdomain origin",
            "test_type":  "http_origin",
        },

        # ── Special characters / parser confusion ──
        {
            "origin":     f"https://{bare_domain}%60.evil.com",
            "label":      "Backtick injection",
            "test_type":  "special_char",
        },
        {
            "origin":     f"https://{bare_domain}_.evil.com",
            "label":      "Underscore bypass",
            "test_type":  "special_char",
        },
        {
            "origin":     f"https://{bare_domain}!.evil.com",
            "label":      "Exclamation bypass",
            "test_type":  "special_char",
        },
        {
            "origin":     f"https://{bare_domain}#.evil.com",
            "label":      "Fragment bypass",
            "test_type":  "special_char",
        },
        {
            "origin":     f"https://{bare_domain}%00.evil.com",
            "label":      "Null byte bypass",
            "test_type":  "special_char",
        },

        # ── Trusted origin itself ──
        {
            "origin":     f"https://{bare_domain}",
            "label":      "Same-origin (baseline)",
            "test_type":  "same_origin_baseline",
        },
        {
            "origin":     f"http://{bare_domain}",
            "label":      "Same domain HTTP baseline",
            "test_type":  "same_origin_baseline",
        },
    ]

    return origins


# ══════════════════════════════════════════════════════════════
# 4. HTTP PROBE
# ══════════════════════════════════════════════════════════════

SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie",
    "x-auth-token", "x-api-key", "x-csrf-token",
    "x-secret", "x-access-token",
}

UNSAFE_METHODS = {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE"}


def probe_cors(
    url: str,
    origin: str,
    method: str = "GET",
    with_credentials: bool = True,
    http_timeout: int = 10,
) -> CORSTestResult:
    """
    Send a real HTTP request with a crafted Origin header.
    Parse all CORS response headers and classify the result.
    """
    result = CORSTestResult(origin_sent=origin)
    headers = {
        "Origin":  origin,
        "User-Agent": "Mozilla/5.0 (CORS-Scanner)",
    }
    if with_credentials:
        # Simulate credentialed request (cookies would be sent by browser)
        headers["Cookie"] = "session=test_cors_probe"

    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            timeout=http_timeout,
            allow_redirects=True,
            verify=False,
        )
        result.http_status = resp.status_code

        # ── Extract CORS headers (case-insensitive) ──
        h = {k.lower(): v for k, v in resp.headers.items()}

        result.acao_header = h.get("access-control-allow-origin")
        result.acac_header = h.get("access-control-allow-credentials")
        result.acam_header = h.get("access-control-allow-methods")
        result.acah_header = h.get("access-control-allow-headers")
        result.acae_header = h.get("access-control-expose-headers")
        result.acma_header = h.get("access-control-max-age")
        result.varies_origin = "origin" in h.get("vary", "").lower()

    except requests.exceptions.RequestException as e:
        result.evidence.append(f"Request failed: {e}")
        return result

    # ── Nothing returned → not vulnerable ──
    if not result.acao_header:
        return result

    acao = result.acao_header.strip()
    creds = (result.acac_header or "").strip().lower() == "true"

    # ═══════════════════════════════
    # CLASSIFY FINDINGS
    # ═══════════════════════════════

    # 1. Wildcard + credentials
    if acao == "*" and creds:
        result.vulnerable = True
        result.finding    = "wildcard_with_credentials"
        result.evidence.append(f"ACAO: * + ACAC: true")

    # 2. Arbitrary origin reflected + credentials
    elif acao == origin and creds and origin not in ("null", "*"):
        if origin not in (f"https://{_get_bare(url)}", f"http://{_get_bare(url)}"):
            result.vulnerable = True
            result.finding    = "origin_reflected_with_credentials"
            result.evidence.append(f"ACAO echoes attacker origin + ACAC: true")

    # 3. Null origin + credentials
    elif origin == "null" and acao == "null" and creds:
        result.vulnerable = True
        result.finding    = "null_origin_with_credentials"
        result.evidence.append("Server reflects null origin with credentials")

    # 4. Arbitrary origin reflected, no credentials
    elif acao == origin and origin not in ("null", "*"):
        if origin not in (f"https://{_get_bare(url)}", f"http://{_get_bare(url)}"):
            result.vulnerable = True
            result.finding    = "origin_reflected_no_credentials"
            result.evidence.append(f"ACAO echoes attacker origin (no credentials)")

    # 5. Wildcard, no credentials
    elif acao == "*" and not creds:
        result.vulnerable = True
        result.finding    = "wildcard_origin_no_credentials"
        result.evidence.append("ACAO: * (public data exposed)")

    # 6. Null, no credentials
    elif origin == "null" and acao == "null" and not creds:
        result.vulnerable = True
        result.finding    = "null_origin_no_credentials"
        result.evidence.append("Server reflects null origin")

    # ── Secondary checks (run regardless of above) ──

    # Vary: Origin missing when ACAO is dynamic
    if acao and acao != "*" and not result.varies_origin:
        if not result.finding:
            result.finding   = "vary_origin_missing"
        result.evidence.append("Vary: Origin header is missing — CDN caching risk")

    # Exposed sensitive headers
    if result.acae_header:
        exposed = [
            h for h in result.acae_header.lower().split(",")
            if h.strip() in SENSITIVE_HEADERS
        ]
        if exposed:
            result.vulnerable = True
            if not result.finding:
                result.finding = "exposed_sensitive_headers"
            result.evidence.append(
                f"Sensitive headers exposed: {', '.join(exposed)}"
            )

    # Overly permissive methods
    if result.acam_header:
        methods_allowed = {
            m.strip().upper() for m in result.acam_header.split(",")
        }
        unsafe = methods_allowed & UNSAFE_METHODS
        if unsafe:
            if not result.finding or result.finding == "none":
                result.finding = "overly_permissive_methods"
            result.evidence.append(
                f"Unsafe methods allowed cross-origin: {', '.join(unsafe)}"
            )

    # Wildcard ACAH
    if result.acah_header and result.acah_header.strip() == "*":
        if not result.finding or result.finding == "none":
            result.finding = "preflight_wildcard_headers"
        result.evidence.append("ACAH: * allows any header cross-origin")

    return result


def probe_preflight(
    url: str,
    origin: str,
    http_timeout: int = 10,
) -> CORSTestResult:
    """
    Send an OPTIONS preflight request and parse CORS response.
    """
    result = CORSTestResult(origin_sent=f"[PREFLIGHT] {origin}")
    headers = {
        "Origin":                         origin,
        "Access-Control-Request-Method":  "POST",
        "Access-Control-Request-Headers": "Content-Type, Authorization, X-Custom-Header",
        "User-Agent":                     "Mozilla/5.0 (CORS-Scanner)",
    }

    try:
        resp = requests.options(
            url,
            headers=headers,
            timeout=http_timeout,
            allow_redirects=False,
            verify=False,
        )
        result.http_status = resp.status_code
        h = {k.lower(): v for k, v in resp.headers.items()}

        result.acao_header = h.get("access-control-allow-origin")
        result.acac_header = h.get("access-control-allow-credentials")
        result.acam_header = h.get("access-control-allow-methods")
        result.acah_header = h.get("access-control-allow-headers")
        result.acma_header = h.get("access-control-max-age")
        result.varies_origin = "origin" in h.get("vary", "").lower()

    except requests.exceptions.RequestException as e:
        result.evidence.append(f"Preflight request failed: {e}")
        return result

    acao = (result.acao_header or "").strip()
    creds = (result.acac_header or "").strip().lower() == "true"

    if acao == origin and creds:
        result.vulnerable = True
        result.finding    = "origin_reflected_with_credentials"
        result.evidence.append("Preflight reflects origin + credentials")
    elif acao == origin:
        result.vulnerable = True
        result.finding    = "origin_reflected_no_credentials"
        result.evidence.append("Preflight reflects arbitrary origin")
    elif acao == "*":
        result.finding  = "wildcard_origin_no_credentials"
        result.evidence.append("Preflight ACAO: *")

    return result


def _get_bare(url: str) -> str:
    """Extract bare domain from URL."""
    m = re.search(r"https?://([^/:]+)", url)
    return m.group(1) if m else url


# ══════════════════════════════════════════════════════════════
# 5. ENDPOINT CHECKER
# ══════════════════════════════════════════════════════════════

def check_endpoint(
    url: str,
    custom_origins: list[str] = [],
    http_timeout:   int = 10,
) -> EndpointResult:
    """
    Run the full CORS test suite against a single endpoint:
      - GET with each origin payload
      - OPTIONS preflight with suspicious origins
      - POST with credentialed origins
    """
    ep = EndpointResult(url=url)

    # Build origin list
    test_origins = build_test_origins(url)

    # Inject any custom origins the agent provided
    for co in custom_origins:
        test_origins.insert(0, {
            "origin":    co,
            "label":     f"Custom agent origin: {co}",
            "test_type": "custom",
        })

    # ── Run GET tests ──
    for o in test_origins:
        origin = o["origin"]

        # GET (credentialed)
        t = probe_cors(url, origin, method="GET",
                       with_credentials=True, http_timeout=http_timeout)
        ep.tests.append(t)

        # OPTIONS preflight for high-value origins
        if o["test_type"] in (
            "null_origin", "arbitrary_origin",
            "pre_domain_bypass", "post_domain_bypass", "subdomain_bypass",
            "http_origin", "custom",
        ):
            pf = probe_preflight(url, origin, http_timeout=http_timeout)
            ep.tests.append(pf)

    # ── POST credentialed for critical cases ──
    for o in test_origins:
        if o["test_type"] in ("null_origin", "arbitrary_origin", "custom"):
            t = probe_cors(url, o["origin"], method="POST",
                           with_credentials=True, http_timeout=http_timeout)
            ep.tests.append(t)

    # ── Aggregate findings ──
    seen_findings = set()
    for t in ep.tests:
        if t.vulnerable or t.finding not in ("none", ""):
            if t.finding and t.finding != "none":
                seen_findings.add(t.finding)

    ep.findings = list(seen_findings)
    ep.vulnerable = any(t.vulnerable for t in ep.tests)

    # ── Determine worst severity ──
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = "info"
    for f in ep.findings:
        if f in FINDINGS:
            sev = FINDINGS[f]["severity"]
            if severity_rank.get(sev, 0) > severity_rank.get(worst, 0):
                worst = sev
    ep.severity = worst

    # ── Collect remediation ──
    rems = []
    for f in ep.findings:
        if f in FINDINGS:
            for r in FINDINGS[f]["remediation"]:
                if r not in rems:
                    rems.append(r)
    ep.remediation = rems

    return ep


def bulk_check(
    urls:           list[str],
    custom_origins: list[str] = [],
    threads:        int = 10,
    http_timeout:   int = 10,
) -> list[EndpointResult]:
    """Check multiple endpoints in parallel."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(check_endpoint, url, custom_origins, http_timeout): url
            for url in urls
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                url = futures[future]
                results.append(EndpointResult(
                    url=url,
                    findings=[f"Check failed: {e}"],
                ))
    return results


# ══════════════════════════════════════════════════════════════
# 6. PARSERS
# ══════════════════════════════════════════════════════════════

def parse_corscanner(stdout: str, stderr: str) -> list[EndpointResult]:
    """
    Parse CORScanner JSON output.
    CORScanner outputs per-URL JSON objects:
    {
      "url": "https://example.com",
      "type": ["origin_reflected"],
      "credentials": "true",
      ...
    }
    """
    results = []

    # ── Try JSON lines ──
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            url  = data.get("url", "unknown")
            ep   = EndpointResult(url=url)

            vuln_types = data.get("type", [])
            if isinstance(vuln_types, str):
                vuln_types = [vuln_types]

            for vt in vuln_types:
                vt_lower = vt.lower().replace(" ", "_").replace("-", "_")
                # Map CORScanner type → our finding key
                mapped = _map_corscanner_type(vt_lower)
                if mapped and mapped not in ep.findings:
                    ep.findings.append(mapped)

            ep.vulnerable = bool(ep.findings)

            # Severity
            severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            worst = "info"
            for f in ep.findings:
                if f in FINDINGS:
                    sev = FINDINGS[f]["severity"]
                    if severity_rank.get(sev, 0) > severity_rank.get(worst, 0):
                        worst = sev
            ep.severity = worst

            # Raw test result
            ep.tests.append(CORSTestResult(
                origin_sent=data.get("origin", "unknown"),
                acao_header=data.get("acao"),
                acac_header=data.get("acac"),
                vulnerable=ep.vulnerable,
                finding=ep.findings[0] if ep.findings else "none",
                evidence=[json.dumps(data)],
            ))

            results.append(ep)
        except json.JSONDecodeError:
            continue

    # ── Fallback: plain text parse ──
    if not results:
        current_url = None
        ep = None
        for line in stdout.splitlines():
            url_m = re.search(r"https?://\S+", line)
            if url_m and ("cors" in line.lower() or "vuln" in line.lower()
                          or "reflect" in line.lower() or "origin" in line.lower()):
                if ep and ep.url:
                    results.append(ep)
                current_url = url_m.group(0)
                ep = EndpointResult(url=current_url, vulnerable=True)
                finding = _classify_plain_line(line)
                if finding:
                    ep.findings.append(finding)
                    ep.severity = FINDINGS.get(finding, {}).get("severity", "medium")
                ep.tests.append(CORSTestResult(
                    origin_sent="parsed",
                    vulnerable=True,
                    finding=finding or "none",
                    evidence=[line],
                ))
        if ep and ep.url:
            results.append(ep)

    return results


def parse_curl_cors(stdout: str, stderr: str, url: str, origin: str) -> CORSTestResult:
    """
    Parse curl -I / -v output for CORS headers.
    Handles both -I (headers only) and -v (verbose) output.
    """
    raw = stdout + "\n" + stderr
    result = CORSTestResult(origin_sent=origin)

    header_map = {
        "access-control-allow-origin":      "acao_header",
        "access-control-allow-credentials": "acac_header",
        "access-control-allow-methods":     "acam_header",
        "access-control-allow-headers":     "acah_header",
        "access-control-expose-headers":    "acae_header",
        "access-control-max-age":           "acma_header",
    }

    for line in raw.splitlines():
        # HTTP status
        status_m = re.match(r"(?:HTTP/[\d.]+|<)\s+(\d{3})", line)
        if status_m:
            result.http_status = int(status_m.group(1))

        # CORS headers  (curl -v shows: < Header: value)
        line_clean = re.sub(r"^[<>*]\s*", "", line).strip()
        colon_idx  = line_clean.find(":")
        if colon_idx > 0:
            hdr_name  = line_clean[:colon_idx].strip().lower()
            hdr_value = line_clean[colon_idx + 1:].strip()
            if hdr_name in header_map:
                setattr(result, header_map[hdr_name], hdr_value)
            if hdr_name == "vary" and "origin" in hdr_value.lower():
                result.varies_origin = True

    # Classify
    acao  = (result.acao_header or "").strip()
    creds = (result.acac_header or "").strip().lower() == "true"

    if acao == origin and creds:
        result.vulnerable = True
        result.finding    = "origin_reflected_with_credentials"
        result.evidence.append("curl: origin reflected + credentials")
    elif acao == origin:
        result.vulnerable = True
        result.finding    = "origin_reflected_no_credentials"
        result.evidence.append("curl: origin reflected")
    elif acao == "*" and creds:
        result.vulnerable = True
        result.finding    = "wildcard_with_credentials"
        result.evidence.append("curl: wildcard + credentials")
    elif acao == "*":
        result.finding  = "wildcard_origin_no_credentials"
        result.evidence.append("curl: ACAO: *")
    elif acao == "null" and origin == "null":
        result.vulnerable = True
        result.finding    = "null_origin_with_credentials" if creds else "null_origin_no_credentials"
        result.evidence.append("curl: null origin accepted")

    return result


def _map_corscanner_type(vt: str) -> Optional[str]:
    """Map CORScanner vulnerability type string → our finding key."""
    mapping = {
        "origin_reflected":                  "origin_reflected_with_credentials",
        "third_party_allowed":               "origin_reflected_no_credentials",
        "wildcard_value":                    "wildcard_origin_no_credentials",
        "wildcard_with_credentials":         "wildcard_with_credentials",
        "null_origin":                       "null_origin_with_credentials",
        "pre_domain_bypass":                 "pre_domain_bypass",
        "post_domain_bypass":                "post_domain_bypass",
        "subdomain_allowed":                 "subdomain_bypass",
        "http_trust":                        "http_origin_trusted_on_https",
        "vary_missing":                      "vary_origin_missing",
    }
    for key, val in mapping.items():
        if key in vt:
            return val
    return None


def _classify_plain_line(line: str) -> Optional[str]:
    """Classify a plain-text CORScanner output line."""
    line_l = line.lower()
    if "wildcard" in line_l and "credential" in line_l:
        return "wildcard_with_credentials"
    if "null" in line_l and "credential" in line_l:
        return "null_origin_with_credentials"
    if "reflect" in line_l and "credential" in line_l:
        return "origin_reflected_with_credentials"
    if "reflect" in line_l:
        return "origin_reflected_no_credentials"
    if "wildcard" in line_l:
        return "wildcard_origin_no_credentials"
    if "null" in line_l:
        return "null_origin_no_credentials"
    return None


# ══════════════════════════════════════════════════════════════
# 7. EXECUTOR
# ══════════════════════════════════════════════════════════════

def safe_execute(cmd: list[str], timeout: int = 600) -> tuple[str, str, int]:
    """Run subprocess safely — no shell, no injection."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool '{cmd[0]}' not installed", -1
    except Exception as e:
        return "", str(e), -1


# ══════════════════════════════════════════════════════════════
# 8. MAIN TOOL FUNCTION
# ══════════════════════════════════════════════════════════════

def cors_misconfig_check(
    tool:       str,
    target:     str,
    args:       list[str] = [],
    endpoints:  list[str] = [],
    origins:    list[str] = [],
) -> dict:
    """
    🔧 Agent Tool: CORS Misconfiguration Checker

    Capabilities:
      ┌──────────────────────────────────────────────────────────────────────┐
      │  WILDCARD ORIGIN          ACAO: * detection                          │
      │  ORIGIN REFLECTION        Arbitrary origin echoing                   │
      │  NULL ORIGIN              Null origin acceptance                     │
      │  CREDENTIAL LEAK          ACAC: true + open ACAO                     │
      │  BYPASS TECHNIQUES        Pre/post-domain, subdomain, HTTP-on-HTTPS  │
      │  PREFLIGHT ANALYSIS       OPTIONS request testing                    │
      │  HEADER EXPOSURE          Sensitive headers via ACAE                 │
      │  METHOD AUDIT             Unsafe methods via ACAM                    │
      │  CACHE POISONING          Vary: Origin missing detection              │
      │  TOOL INTEGRATION         CORScanner, curl, manual (requests)        │
      └──────────────────────────────────────────────────────────────────────┘

    Args:
        tool:      "corscanner" | "curl" | "manual"
        target:    URL or domain (e.g. "https://example.com" or "example.com")
        args:      Raw tool arguments — agent decides
        endpoints: List of specific URLs to test (optional)
        origins:   Custom origins to inject (optional)

    Tool args reference:
      corscanner:
        Basic:    ["-u", "https://example.com"]
        File:     ["-i", "urls.txt"]
        Threads:  ["-t", "50"]
        Headers:  ["-H", "Cookie: session=abc"]
        Verbose:  ["-v"]
        JSON:     ["-o", "json"]   → auto-injected

      curl:
        Headers:  ["-H", "Cookie: session=abc", "-H", "Authorization: Bearer xyz"]
        Follow:   ["-L"]
        Verbose:  ["-v"]           → auto-injected for header parsing
        Timeout:  ["--max-time", "10"]

      manual:
        (pure Python — no args needed)
        Threads and timeout controlled internally.

    Returns:
        Structured JSON: endpoints → tests → CORS headers → findings → remediation
    """
    start = time.time()

    # ══════════════════════════════
    # VALIDATE
    # ══════════════════════════════
    try:
        req = CORSCheckRequest(
            tool=tool, target=target, args=args,
            endpoints=endpoints, origins=origins,
        )
    except Exception as e:
        return CORSScanResult(
            success=False, tool=tool, target=target,
            command="", error=f"Validation: {e}"
        ).model_dump()

    # Normalise target to URL
    if not target.startswith("http"):
        target = f"https://{target}"

    results:     list[EndpointResult] = []
    command_str: str = ""
    raw_output:  str = ""
    error_msg:   Optional[str] = None

    # Build full URL list
    all_urls = [target] + [
        u if u.startswith("http") else f"{target.rstrip('/')}/{u.lstrip('/')}"
        for u in req.endpoints
    ]
    all_urls = list(dict.fromkeys(all_urls))   # deduplicate, preserve order

    # ══════════════════════════════
    # TOOL: MANUAL
    # ══════════════════════════════
    if tool == "manual":
        command_str = f"manual_cors_check({target}, {len(all_urls)} endpoints)"
        results = bulk_check(
            urls=all_urls,
            custom_origins=req.origins,
            threads=10,
            http_timeout=10,
        )

    # ══════════════════════════════
    # TOOL: CORSCANNER
    # ══════════════════════════════
    elif tool == "corscanner":
        import tempfile, os

        tmp_file = None
        cmd = ["python3", "-m", "CORScanner"]

        if len(all_urls) > 1:
            tmp_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="cors_urls_"
            )
            tmp_file.write("\n".join(all_urls))
            tmp_file.close()
            cmd.extend(["-i", tmp_file.name])
        else:
            cmd.extend(["-u", target])

        # Force JSON output
        if "-o" not in req.args:
            cmd.extend(["-o", "json"])

        cmd += list(req.args)
        command_str = " ".join(cmd)

        stdout, stderr, rc = safe_execute(cmd, req.timeout)
        raw_output = (stdout or stderr)[:5000]

        results = parse_corscanner(stdout, stderr)

        # Enrich with our own manual check for any missed URLs
        checked_urls = {r.url for r in results}
        missed = [u for u in all_urls if u not in checked_urls]
        if missed:
            extra = bulk_check(missed, custom_origins=req.origins, threads=10)
            results.extend(extra)

        if tmp_file and os.path.exists(tmp_file.name):
            os.unlink(tmp_file.name)

        if rc != 0 and not results:
            error_msg = stderr[:500]

    # ══════════════════════════════
    # TOOL: CURL
    # ══════════════════════════════
    elif tool == "curl":
        test_origins_for_curl = [
            "null",
            "https://evil.com",
            f"https://evil-{_get_bare(target)}",
            f"https://{_get_bare(target)}.evil.com",
            f"https://evil.{_get_bare(target)}",
            f"http://{_get_bare(target)}",
        ] + req.origins

        for url in all_urls:
            ep = EndpointResult(url=url)

            for origin in test_origins_for_curl:
                # Build curl command
                cmd = [
                    "curl", "-v", "-s", "--max-time", "10",
                    "-H", f"Origin: {origin}",
                    "-H", "Cookie: session=cors_test",
                    "-X", "GET",
                ]
                cmd += list(req.args)
                cmd.append(url)

                command_str = " ".join(cmd)
                stdout, stderr, rc = safe_execute(cmd, req.timeout)
                raw_output += (stderr or stdout)[:1000]

                t = parse_curl_cors(stdout, stderr, url, origin)
                ep.tests.append(t)

                # Also OPTIONS preflight via curl
                pf_cmd = [
                    "curl", "-v", "-s", "--max-time", "10",
                    "-X", "OPTIONS",
                    "-H", f"Origin: {origin}",
                    "-H", "Access-Control-Request-Method: POST",
                    "-H", "Access-Control-Request-Headers: Content-Type, Authorization",
                ]
                pf_cmd += list(req.args)
                pf_cmd.append(url)

                pf_stdout, pf_stderr, _ = safe_execute(pf_cmd, req.timeout)
                pf_t = parse_curl_cors(pf_stdout, pf_stderr, url, f"[PREFLIGHT] {origin}")
                ep.tests.append(pf_t)

            # Aggregate
            seen = set()
            for t in ep.tests:
                if t.finding and t.finding != "none":
                    seen.add(t.finding)
            ep.findings   = list(seen)
            ep.vulnerable = any(t.vulnerable for t in ep.tests)

            severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            worst = "info"
            for f in ep.findings:
                if f in FINDINGS:
                    sev = FINDINGS[f]["severity"]
                    if severity_rank.get(sev, 0) > severity_rank.get(worst, 0):
                        worst = sev
            ep.severity = worst

            rems = []
            for f in ep.findings:
                if f in FINDINGS:
                    for r in FINDINGS[f]["remediation"]:
                        if r not in rems:
                            rems.append(r)
            ep.remediation = rems
            results.append(ep)

    # ══════════════════════════════
    # BUILD RESULT
    # ══════════════════════════════
    vulnerable = [r for r in results if r.vulnerable]

    return CORSScanResult(
        success=len(results) > 0,
        tool=tool,
        target=target,
        command=command_str,
        total_endpoints=len(results),
        total_vulnerable=len(vulnerable),
        endpoints=results,
        raw_output=raw_output[:5000] if raw_output else None,
        error=error_msg,
        execution_time=round(time.time() - start, 2),
    ).model_dump()


# ══════════════════════════════════════════════════════════════
# 9. TOOL DEFINITION (for LLM)
# ══════════════════════════════════════════════════════════════

CORS_MISCONFIG_TOOL_DEFINITION = {
    "name": "cors_misconfig_check",
    "description": (
        "Test a target for CORS misconfigurations including: "
        "wildcard origin, arbitrary origin reflection, null origin acceptance, "
        "credential leakage (ACAC: true), pre/post-domain bypass, "
        "subdomain bypass, HTTP origin on HTTPS, cache poisoning (Vary: Origin missing), "
        "sensitive header exposure, and unsafe method allowance. "
        "Supports CORScanner (automated), curl (header-level), "
        "and manual (built-in Python requests with 20+ payloads)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "enum": ["corscanner", "curl", "manual"],
                "description": (
                    "corscanner = automated CORS scanner (JSON output) | "
                    "curl       = raw HTTP header inspection | "
                    "manual     = built-in Python checker with full payload suite"
                ),
            },
            "target": {
                "type": "string",
                "description": "Target URL or domain (e.g. 'https://example.com' or 'example.com')",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Raw tool arguments. Examples:\n"
                    "corscanner: ['-t', '50', '-v']\n"
                    "curl:       ['-H', 'Cookie: session=abc', '-L', '--max-time', '15']\n"
                    "manual:     [] (no args needed)"
                ),
            },
            "endpoints": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Specific endpoints to test in addition to root target. "
                    "e.g. ['/api/v1/user', '/api/admin', 'https://api.example.com/data']"
                ),
            },
            "origins": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Custom origins to inject. "
                    "e.g. ['https://attacker.com', 'null', 'https://evil-example.com']"
                ),
            },
        },
        "required": ["tool", "target"],
    },
}


# ══════════════════════════════════════════════════════════════
# 10. USAGE EXAMPLES
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    # ─────────────────────────────
    # 1. Manual — full payload suite
    # ─────────────────────────────
    r = cors_misconfig_check(
        tool="manual",
        target="https://example.com",
        endpoints=["/api/v1/user", "/api/v1/admin", "/api/v1/data"],
    )
    print("=== MANUAL FULL CHECK ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 2. Manual — custom origins
    # ─────────────────────────────
    r = cors_misconfig_check(
        tool="manual",
        target="https://api.example.com",
        origins=["https://attacker.com", "null", "https://evil-example.com"],
    )
    print("=== MANUAL CUSTOM ORIGINS ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 3. CORScanner
    # ─────────────────────────────
    r = cors_misconfig_check(
        tool="corscanner",
        target="https://example.com",
        args=["-t", "50", "-v"],
        endpoints=["/api/user", "/api/admin"],
    )
    print("=== CORSCANNER ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 4. curl — with auth header
    # ─────────────────────────────
    r = cors_misconfig_check(
        tool="curl",
        target="https://api.example.com",
        args=["-H", "Authorization: Bearer test_token", "-L"],
        endpoints=["/api/v1/profile", "/api/v1/payments"],
    )
    print("=== CURL WITH AUTH ===")
    print(json.dumps(r, indent=2))

    # ─────────────────────────────
    # 5. Single endpoint deep check
    # ─────────────────────────────
    r = cors_misconfig_check(
        tool="manual",
        target="https://api.example.com/v1/sensitive-data",
    )
    print("=== SINGLE ENDPOINT ===")
    print(json.dumps(r, indent=2))